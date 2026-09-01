//! INT10-C: Do not assume a positive remainder when using the % operator
//!
//! The C Standard states that if either operand of the modulo (%) operator is negative,
//! the sign of the result is implementation-defined. This means the result can be negative
//! even when you might expect a positive value. This is particularly dangerous when:
//! 1. The result is used as an array index (can cause out-of-bounds access)
//! 2. The result is expected to be positive for algorithm correctness
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int insert(int index, int *list, int size, int value) {
//!     if (size != 0) {
//!         index = (index + 1) % size;  // Can be negative!
//!         list[index] = value;         // Undefined behavior if negative
//!         return index;
//!     }
//!     return -1;
//! }
//! ```
//!
//! **Non-compliant (abs() is not a fix):**
//! ```c
//! index = abs((index + 1) % size);  // abs(INT_MIN) is undefined behavior
//! ```
//!
//! **Compliant (use unsigned types):**
//! ```c
//! size_t insert(size_t index, int *list, size_t size, int value) {
//!     if (size != 0 && size != SIZE_MAX) {
//!         index = (index + 1) % size;  // Always positive (unsigned)
//!         list[index] = value;
//!         return index;
//!     }
//!     return SIZE_MAX;  // Error indicator
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval::{self, MacroConstantMap};
use crate::analyze::context::ProjectContext;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::overflow_helpers;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Int10C {
    /// One-level typedef alias map (`word_t` -> `unsigned long`, `paddr_t` ->
    /// `word_t`, ...), populated project-wide by `set_project_context`.
    /// Resolved recursively by `overflow_helpers::typedef_chain_is_unsigned`
    /// so a multi-level, cross-file typedef family is recognized as
    /// unsigned even though `type_map` only records the alias name as
    /// written (task 657).
    typedef_types: RefCell<HashMap<String, String>>,
    /// Project-wide compile-time constants (enum constants, `#define`s,
    /// file-scope `static const`), populated by `set_project_context` and
    /// merged with per-file constants in `check`. Lets a modulo operand
    /// that's an enum constant with a provably non-negative *value* clear
    /// the check even when its enum *type* is signed (task 673).
    project_macros: RefCell<MacroConstantMap>,
}

impl Int10C {
    pub fn new() -> Self {
        Self {
            typedef_types: RefCell::new(HashMap::new()),
            project_macros: RefCell::new(MacroConstantMap::new()),
        }
    }
}

impl CertRule for Int10C {
    fn rule_id(&self) -> &'static str {
        "INT10-C"
    }

    fn description(&self) -> &'static str {
        "Do not assume a positive remainder when using the % operator"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "INT10-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.typedef_types.borrow_mut() = context.typedef_types.clone();
        *self.project_macros.borrow_mut() = context.macro_constants.clone();
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let type_map = overflow_helpers::collect_variable_types(node, source);
        let macros =
            const_eval::merged_macro_constants(&self.project_macros.borrow(), node, source);
        self.check_modulo_usage(node, source, &mut violations, &type_map, &macros);
        violations
    }
}

impl Int10C {
    fn check_modulo_usage(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
        macros: &MacroConstantMap,
    ) {
        // Scope type_map per function to avoid cross-function name collisions
        // (e.g., a same-named variable of a different signedness in a different
        // function). Memoized per enclosing function_definition node id so it's
        // only computed once even though many candidates share the same function.
        let mut fn_type_maps: HashMap<usize, HashMap<String, String>> = HashMap::new();

        for n in query::find_descendants_of_kind(*node, "binary_expression") {
            if let Some(operator) = n.child_by_field_name("operator") {
                let op_text = get_node_text(&operator, source);

                if op_text == "%" {
                    let scoped_type_map: &HashMap<String, String> =
                        match overflow_helpers::enclosing_function_definition(&n) {
                            Some(func_node) => {
                                fn_type_maps.entry(func_node.id()).or_insert_with(|| {
                                    overflow_helpers::collect_variable_types(&func_node, source)
                                })
                            }
                            None => type_map,
                        };

                    // Check if this is a signed modulo operation
                    if self.is_potentially_signed_modulo(&n, source, scoped_type_map, macros) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: "Modulo operator used with potentially signed operands. \
                                     The result of % with negative operands is implementation-defined \
                                     and can be negative. Use unsigned types (size_t, unsigned int) \
                                     or explicitly handle negative remainders."
                                .to_string(),
                            severity: self.severity(),
                            line: operator.start_position().row + 1,
                            column: operator.start_position().column + 1,
                            file_path: String::new(),
                            suggestion: Some(
                                "Convert operands to unsigned types (size_t, unsigned int) \
                                 or add explicit checks for negative values"
                                    .to_string(),
                            ),
                            requires_manual_review: Some(true),
                        });
                    }
                }
            }
        }
    }

    /// Check if a modulo operation might involve signed operands
    fn is_potentially_signed_modulo(
        &self,
        modulo_node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
        macros: &MacroConstantMap,
    ) -> bool {
        // Get left and right operands
        let left = modulo_node.child_by_field_name("left");
        let right = modulo_node.child_by_field_name("right");

        if left.is_none() || right.is_none() {
            return false;
        }

        let left_node = left.unwrap();
        let right_node = right.unwrap();

        // Check if either operand appears to be unsigned
        let left_text = get_node_text(&left_node, source);
        let right_text = get_node_text(&right_node, source);

        // If either operand is explicitly unsigned, it's likely safe
        let expr_is_unsigned = self.looks_unsigned(&left_text) || self.looks_unsigned(&right_text);

        if expr_is_unsigned {
            return false;
        }

        // Check type_map for identifiers within each operand
        if self.operand_has_unsigned_type(&left_node, source, type_map)
            || self.operand_has_unsigned_type(&right_node, source, type_map)
        {
            return false;
        }

        // An operand identifier whose *value* resolves to a compile-time
        // constant (an enum constant, `#define`, or file-scope `static
        // const`) that's non-negative can't produce a negative remainder,
        // regardless of its declared type's signedness -- e.g. an
        // `interrupt_t` enum constant set to a macro like `IRQ_INT_OFFSET`
        // (0x20) is provably non-negative even though the enum itself has
        // an unrelated negative member (`int_invalid = -1`) and is
        // therefore a signed type overall (task 673).
        if self.operand_is_nonnegative_constant(&left_node, source, macros)
            || self.operand_is_nonnegative_constant(&right_node, source, macros)
        {
            return false;
        }

        // Field expressions (e.g., self->field) — we can't resolve struct member
        // types without struct definitions, so don't assume signed
        if left_node.kind() == "field_expression" || right_node.kind() == "field_expression" {
            return false;
        }

        // Check if we're in a function with size_t parameters
        if self.is_in_function_with_unsigned_params(modulo_node, source) {
            return false;
        }

        true
    }

    /// Check if any identifier in the operand resolves to an unsigned type
    fn operand_has_unsigned_type(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        let typedef_types = self.typedef_types.borrow();
        query::find_first_descendant(*node, |n| {
            if n.kind() == "identifier" {
                let name = get_node_text(&n, source);
                if let Some(t) = type_map.get(name) {
                    return t.contains("size_t")
                        || t.contains("unsigned")
                        || t.contains("uint")
                        || overflow_helpers::is_short_unsigned_typedef(t)
                        // `t` is the alias name as written (e.g. "word_t",
                        // "paddr_t") -- resolve the full, possibly
                        // cross-file typedef chain before giving up (task
                        // 657).
                        || overflow_helpers::typedef_chain_is_unsigned(t, &typedef_types);
                }
            }
            // `sizeof(...)` always yields `size_t`, regardless of the sized
            // expression's own type.
            if n.kind() == "sizeof_expression" {
                return true;
            }
            // An explicit cast to a typedef'd name (e.g. `(seL4_Word)&x`) --
            // resolve the cast's target type through the same typedef chain.
            if n.kind() == "cast_expression" {
                if let Some(type_node) = n.child_by_field_name("type") {
                    let cast_type = get_node_text(&type_node, source);
                    if cast_type.contains("unsigned")
                        || overflow_helpers::typedef_chain_is_unsigned(cast_type, &typedef_types)
                    {
                        return true;
                    }
                }
            }
            // For field expressions like self->field, we can't resolve the type
            // but we know it's a struct access — check text heuristic
            if n.kind() == "field_expression" {
                let text = get_node_text(&n, source);
                if self.looks_unsigned(&text) {
                    return true;
                }
            }
            false
        })
        .is_some()
    }

    /// Check if any identifier in the operand resolves, via compile-time
    /// constant folding, to a known non-negative value. Deliberately
    /// scoped to *identifier* operands only (an enum constant, `#define`,
    /// or `static const` name) — not to bare integer literals written
    /// directly in the modulo expression, since a literal on one side
    /// (e.g. `x % 60`) says nothing about whether the *other*, unresolved
    /// operand can be negative, and treating it as safe would suppress
    /// genuine findings (task 673).
    fn operand_is_nonnegative_constant(
        &self,
        node: &Node,
        source: &str,
        macros: &MacroConstantMap,
    ) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() == "identifier" {
                let name = get_node_text(&n, source);
                if let Some(&value) = macros.get(name) {
                    return value >= 0;
                }
            }
            false
        })
        .is_some()
    }

    /// Check if an expression appears to use unsigned types
    fn looks_unsigned(&self, text: &str) -> bool {
        // Common unsigned type patterns
        text.contains("size_t")
            || text.contains("unsigned")
            || text.contains("SIZE_MAX")
            || text.contains("UINT_MAX")
            // Unsigned literal suffix
            || text.ends_with('u')
            || text.ends_with('U')
            || text.ends_with("ul")
            || text.ends_with("UL")
            || text.ends_with("ull")
            || text.ends_with("ULL")
    }

    /// Check if node is within a function that has unsigned type parameters
    fn is_in_function_with_unsigned_params(&self, node: &Node, source: &str) -> bool {
        let mut current = node.parent();

        while let Some(parent) = current {
            if parent.kind() == "function_definition" {
                // Look for parameter list
                if let Some(declarator) = parent.child_by_field_name("declarator") {
                    let params_text = get_node_text(&declarator, source);
                    // Check if parameters contain unsigned types
                    if params_text.contains("size_t") || params_text.contains("unsigned") {
                        return true;
                    }
                }
                break;
            }
            current = parent.parent();
        }

        false
    }
}
