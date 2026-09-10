//! INT16-C: Do not make assumptions about representation of signed integers
//!
//! The C Standard permits three different representations for signed integers:
//! - Two's complement
//! - One's complement
//! - Sign and magnitude
//!
//! Bitwise operations on signed integers produce implementation-defined results.
//! Always use unsigned integers for bitwise operations.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int value;
//! if (value & 0x1 != 0) {  // Bitwise operation on signed int
//!     // Check if odd - fails on one's complement
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! // Option 1: Use modulo operator
//! if (value % 2 != 0) {
//!     // Correct way to check if odd
//! }
//!
//! // Option 2: Use unsigned integers
//! unsigned int value;
//! if (value & 0x1 != 0) {
//!     // Bitwise operations are safe on unsigned types
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::FunctionCfg;
use crate::analyze::const_eval::MacroConstantMap;
use crate::analyze::context::ProjectContext;
use crate::analyze::value_range::RangeAnalysisResult;
use crate::analyze::vra_access;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{
    get_node_text, resolve_field_expression_type, resolve_identifier_declarator,
};
use crate::utility::cert_c::overflow_helpers::typedef_chain_is_unsigned;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashMap;
use tree_sitter::Node;

/// What a declaration says about an integer object's sign.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Signedness {
    Signed,
    Unsigned,
}

#[derive(Default)]
pub struct Int16C {
    /// Per-function CFGs for the file being checked, injected by the driver.
    function_cfgs: RefCell<HashMap<usize, FunctionCfg>>,
    /// Per-function value ranges for the same file, injected alongside them.
    vra_results: RefCell<HashMap<usize, RangeAnalysisResult>>,
    /// `struct tag -> {field -> type text}` from the prescan, so the
    /// assignment check can read the declared type of `s->field`.
    struct_field_types: RefCell<HashMap<String, HashMap<String, String>>>,
    /// One-level typedef alias map from the prescan, walked by
    /// `typedef_chain_is_unsigned` so a destination spelled `u32` or
    /// `lua_Unsigned` is recognized as the unsigned object it is.
    typedef_types: RefCell<HashMap<String, String>>,
}

impl CertRule for Int16C {
    fn rule_id(&self) -> &'static str {
        "INT16-C"
    }

    fn description(&self) -> &'static str {
        "Do not make assumptions about representation of signed integers"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "INT16-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.struct_field_types.borrow_mut() = context.struct_field_types.clone();
        *self.typedef_types.borrow_mut() = context.typedef_types.clone();
    }

    fn set_function_cfgs(&self, cfgs: &HashMap<usize, FunctionCfg>) {
        *self.function_cfgs.borrow_mut() = cfgs.clone();
    }

    fn set_vra_results(&self, results: &HashMap<usize, RangeAnalysisResult>) {
        *self.vra_results.borrow_mut() = results.clone();
    }

    fn needs_vra(&self) -> bool {
        true
    }

    // Every question this rule asks about a name -- "is this operand a signed
    // integer?", "is this destination an unsigned one?" -- is answered by
    // resolving THAT occurrence to the declaration in scope at that point
    // (`resolve_identifier_declarator`: nearest enclosing block, else the
    // function's parameter list, else a file-scope global). A previous
    // version kept one file-wide `name -> declaration` map instead, and 119
    // of 120 adjudicated signed->unsigned findings were false: lua's
    // `findindex` returns its own `unsigned int i`, and was reported because
    // an unrelated `int i` elsewhere in ltable.c put the name in the map;
    // curl's `long certverifyresult` was reported as an unsigned destination
    // because a name's ABSENCE from a signed map was taken as unsignedness.
    // A name is not a variable; the declaration that binds it here is.
    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.find_bitwise_operations(node, source, &mut violations);
        self.find_signed_to_unsigned_conversions(node, source, &mut violations);
        violations
    }
}

impl Int16C {
    // -----------------------------------------------------------------------
    // Declared-type resolution
    // -----------------------------------------------------------------------

    /// The sign of the integer object `name` denotes at `ident`, after
    /// stripping `unwrap` levels of pointer/array declarator (`0` for the
    /// object itself, `1` for `*p` or `a[i]`). `None` when the name does not
    /// resolve, is not an integer scalar at that depth (a pointer, an array,
    /// a function, a struct), or is spelled with a type this rule does not
    /// classify.
    fn declared_signedness(
        &self,
        ident: &Node,
        name: &str,
        source: &str,
        unwrap: usize,
    ) -> Option<Signedness> {
        let (decl, mut declarator) = resolve_identifier_declarator(ident, name, source)?;
        for _ in 0..unwrap {
            if !matches!(declarator.kind(), "pointer_declarator" | "array_declarator") {
                return None;
            }
            declarator = declarator.child_by_field_name("declarator")?;
        }
        if declarator.kind() != "identifier" {
            return None;
        }
        self.type_text_signedness(&Self::base_type_text(&decl, source)?)
    }

    /// The type-specifier tokens of a `declaration`/`parameter_declaration`
    /// with qualifiers and storage class dropped (`static const unsigned
    /// int x` -> `"unsigned int"`). `None` for a struct/union/enum specifier
    /// (not an integer) or when no specifier is present (a declarator
    /// tree-sitter could not attach a type to).
    fn base_type_text(decl: &Node, source: &str) -> Option<String> {
        let mut parts: Vec<&str> = Vec::new();
        for i in 0..decl.child_count() {
            let Some(child) = decl.child(i) else {
                continue;
            };
            match child.kind() {
                "primitive_type" | "sized_type_specifier" | "type_identifier" => {
                    parts.extend(get_node_text(&child, source).split_whitespace());
                }
                "struct_specifier" | "union_specifier" | "enum_specifier" => return None,
                _ => {}
            }
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    }

    /// Classify a bare type spelling. The unsigned side follows typedefs
    /// through the prescan's alias map, because an unsigned DESTINATION
    /// only ever keeps a finding the rule already made (the previous
    /// version reported on the destination's absence from its signed map,
    /// which every typedef'd name satisfied). The signed side is spelling
    /// only, matching what the previous version tracked -- widening it
    /// through typedefs (`i64`, `lua_Integer`) would be a recall change to
    /// measure on its own.
    fn type_text_signedness(&self, base: &str) -> Option<Signedness> {
        if typedef_chain_is_unsigned(base, &self.typedef_types.borrow()) {
            return Some(Signedness::Unsigned);
        }
        if Self::is_signed_integer_spelling(base) {
            return Some(Signedness::Signed);
        }
        None
    }

    /// Standard signed integer type spellings. Plain `char` is deliberately
    /// absent: its sign is implementation-defined, so a bitwise operation
    /// on it is not the assumption this rule is about, and the previous
    /// version did not track it either.
    fn is_signed_integer_spelling(base: &str) -> bool {
        matches!(
            base,
            "int"
                | "signed"
                | "signed int"
                | "short"
                | "short int"
                | "signed short"
                | "signed short int"
                | "long"
                | "long int"
                | "signed long"
                | "signed long int"
                | "long long"
                | "long long int"
                | "signed long long"
                | "signed long long int"
                | "signed char"
        )
    }

    /// Declared type of the identifier at `ident` in the `"struct tag *"`
    /// spelling `resolve_field_expression_type`'s type map expects. `None`
    /// for an anonymous struct, an array, or a function declarator.
    fn declared_type_text(&self, ident: &Node, name: &str, source: &str) -> Option<String> {
        let (decl, mut declarator) = resolve_identifier_declarator(ident, name, source)?;
        let mut parts: Vec<String> = Vec::new();
        for i in 0..decl.child_count() {
            let Some(child) = decl.child(i) else {
                continue;
            };
            match child.kind() {
                "primitive_type" | "sized_type_specifier" | "type_identifier" => {
                    parts.push(get_node_text(&child, source).to_string());
                }
                "struct_specifier" | "union_specifier" | "enum_specifier" => {
                    let tag = child.child_by_field_name("name")?;
                    let keyword = child.kind().trim_end_matches("_specifier");
                    parts.push(format!("{} {}", keyword, get_node_text(&tag, source)));
                }
                _ => {}
            }
        }
        if parts.is_empty() {
            return None;
        }
        let mut text = parts.join(" ");
        while declarator.kind() == "pointer_declarator" {
            text.push_str(" *");
            declarator = declarator.child_by_field_name("declarator")?;
        }
        if declarator.kind() != "identifier" {
            return None;
        }
        Some(text)
    }

    /// True when the identifier at `ident` is declared as a signed integer
    /// object in the scope of that occurrence.
    fn is_signed_integer_here(&self, ident: &Node, source: &str) -> bool {
        let name = get_node_text(ident, source);
        self.declared_signedness(ident, name, source, 0) == Some(Signedness::Signed)
    }

    /// Positive evidence that the assignment target `left` denotes an
    /// unsigned integer object: a name declared unsigned in this scope,
    /// `*p` or `a[i]` over a pointer/array to unsigned, or `s->field` whose
    /// field the prescan recorded with an unsigned type. Anything the rule
    /// cannot resolve is `false` -- "not known to be signed" is not
    /// "unsigned", which is the inference the previous version made.
    fn lvalue_is_unsigned_integer(&self, left: &Node, source: &str) -> bool {
        match left.kind() {
            "identifier" => {
                let name = get_node_text(left, source);
                self.declared_signedness(left, name, source, 0) == Some(Signedness::Unsigned)
            }
            "parenthesized_expression" => left
                .named_child(0)
                .is_some_and(|inner| self.lvalue_is_unsigned_integer(&inner, source)),
            "pointer_expression" | "subscript_expression" => {
                let is_deref = left.kind() == "subscript_expression"
                    || left
                        .child_by_field_name("operator")
                        .is_some_and(|op| get_node_text(&op, source) == "*");
                if !is_deref {
                    return false;
                }
                let Some(arg) = left.child_by_field_name("argument") else {
                    return false;
                };
                if arg.kind() != "identifier" {
                    return false;
                }
                let name = get_node_text(&arg, source);
                self.declared_signedness(&arg, name, source, 1) == Some(Signedness::Unsigned)
            }
            "field_expression" => self
                .field_type_text(left, source)
                .is_some_and(|ty| self.field_type_is_unsigned_integer(&ty)),
            _ => false,
        }
    }

    /// The prescan-recorded type of the field `expr` (`s->count`,
    /// `a.b->c`) denotes, resolved from the base identifier's declaration
    /// in scope at the expression.
    fn field_type_text(&self, expr: &Node, source: &str) -> Option<String> {
        let mut base = expr.child_by_field_name("argument")?;
        loop {
            base = match base.kind() {
                "identifier" => break,
                "field_expression" | "pointer_expression" => {
                    base.child_by_field_name("argument")?
                }
                "parenthesized_expression" => base.named_child(0)?,
                _ => return None,
            };
        }
        let base_name = get_node_text(&base, source);
        let base_type = self.declared_type_text(&base, base_name, source)?;
        let type_map = HashMap::from([(base_name.to_string(), base_type)]);
        resolve_field_expression_type(expr, source, &type_map, &self.struct_field_types.borrow())
    }

    /// A recorded field type is an unsigned integer object: no pointer
    /// indirection, and its spelling (qualifiers dropped) is unsigned.
    fn field_type_is_unsigned_integer(&self, field_type: &str) -> bool {
        if field_type.contains('*') {
            return false;
        }
        let base: Vec<&str> = field_type
            .split_whitespace()
            .filter(|w| !matches!(*w, "const" | "volatile"))
            .collect();
        self.type_text_signedness(&base.join(" ")) == Some(Signedness::Unsigned)
    }

    // -----------------------------------------------------------------------
    // Bitwise operations on signed operands
    // -----------------------------------------------------------------------

    /// Find bitwise operations involving signed integer variables
    fn find_bitwise_operations(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kinds(*node, &["binary_expression", "unary_expression"])
        {
            // Check binary bitwise operations: &, |, ^, <<, >>
            if n.kind() == "binary_expression" {
                if let Some(operator) = n.child_by_field_name("operator") {
                    let op_text = get_node_text(&operator, source);

                    // Bitwise operators
                    let is_bitwise_op =
                        matches!(op_text, "&" | "|" | "^" | "<<" | ">>" | "&=" | "|=" | "^=");

                    if is_bitwise_op {
                        // Check left and right operands
                        if let Some(left) = n.child_by_field_name("left") {
                            self.check_operand_for_violation(&left, source, violations, op_text);
                        }
                        if let Some(right) = n.child_by_field_name("right") {
                            self.check_operand_for_violation(&right, source, violations, op_text);
                        }
                    }
                }
            } else {
                // Check unary bitwise NOT operation: ~
                if let Some(operator) = n.child_by_field_name("operator") {
                    let op_text = get_node_text(&operator, source);

                    if op_text == "~" {
                        if let Some(argument) = n.child_by_field_name("argument") {
                            self.check_operand_for_violation(&argument, source, violations, "~");
                        }
                    }
                }
            }
        }
    }

    /// Report `operand` when it is, or directly contains, an identifier
    /// declared as a signed integer in the scope of that occurrence.
    fn check_operand_for_violation(
        &self,
        operand: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        operator: &str,
    ) {
        if operand.kind() == "identifier" {
            if self.is_signed_integer_here(operand, source) {
                self.report_bitwise(operand, source, operator, violations);
            }
            return;
        }

        // Complex expressions: check the identifiers one level down.
        for i in 0..operand.child_count() {
            if let Some(child) = operand.child(i) {
                if child.kind() == "identifier" && self.is_signed_integer_here(&child, source) {
                    self.report_bitwise(&child, source, operator, violations);
                }
            }
        }
    }

    fn report_bitwise(
        &self,
        ident: &Node,
        source: &str,
        operator: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let name = get_node_text(ident, source);
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            message: format!(
                "Bitwise operation '{}' on signed integer variable '{}'. \
                 Signed integer representation is implementation-defined. \
                 Use unsigned integers for bitwise operations or use arithmetic operators instead.",
                operator, name
            ),
            severity: self.severity(),
            line: ident.start_position().row + 1,
            column: ident.start_position().column + 1,
            file_path: String::new(),
            suggestion: Some(format!(
                "Change '{}' to 'unsigned int {}' or avoid bitwise operations on signed integers",
                name, name
            )),
            requires_manual_review: None,
        });
    }

    // -----------------------------------------------------------------------
    // Signed value stored into an unsigned object
    // -----------------------------------------------------------------------

    /// Detect signed-to-unsigned conversions without range checks.
    fn find_signed_to_unsigned_conversions(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kinds(
            *node,
            &[
                "function_definition",
                "declaration",
                "assignment_expression",
            ],
        ) {
            match n.kind() {
                "function_definition" => {
                    // Check function definitions for unsigned return type + signed return value
                    if self.has_unsigned_return_type(&n, source) {
                        if let Some(body) = n.child_by_field_name("body") {
                            self.check_unsigned_return_signed(&body, source, violations);
                        }
                    }
                }
                "declaration" => {
                    // Check declarations: unsigned var = signed_var
                    self.check_unsigned_init_from_signed(&n, source, violations);
                }
                _ => {
                    // Check assignments: unsigned_var = signed_var
                    self.check_unsigned_assign_from_signed(&n, source, violations);
                }
            }
        }
    }

    /// The function returns an unsigned integer OBJECT. A pointer-returning
    /// function (`const unsigned char *f(...)`) does not: its `unsigned`
    /// describes the pointee, and returning a signed integer from it is a
    /// different defect (sqlite's `sqlite3_value_text`-style accessor was
    /// reported here for exactly that misreading).
    fn has_unsigned_return_type(&self, func_node: &Node, source: &str) -> bool {
        let mut parts: Vec<&str> = Vec::new();
        let mut cursor = func_node.walk();
        for child in func_node.children(&mut cursor) {
            match child.kind() {
                "pointer_declarator" => return false,
                "function_declarator" => break,
                "primitive_type" | "sized_type_specifier" | "type_identifier" => {
                    parts.extend(get_node_text(&child, source).split_whitespace());
                }
                "struct_specifier" | "union_specifier" | "enum_specifier" => return false,
                _ => {}
            }
        }
        !parts.is_empty()
            && self.type_text_signedness(&parts.join(" ")) == Some(Signedness::Unsigned)
    }

    /// Check return statements that return a signed variable from an unsigned function.
    fn check_unsigned_return_signed(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for ret in query::find_descendants_of_kind(*node, "return_statement") {
            // Get the returned expression (skip "return" keyword)
            for i in 0..ret.child_count() {
                if let Some(child) = ret.child(i) {
                    if child.kind() == "identifier" && self.is_signed_integer_here(&child, source) {
                        let name = get_node_text(&child, source).to_string();
                        if !self.has_non_negative_guard(&ret, &name, source) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                message: format!(
                                    "Signed variable '{}' returned as unsigned without range check",
                                    name
                                ),
                                severity: self.severity(),
                                line: ret.start_position().row + 1,
                                column: ret.start_position().column + 1,
                                file_path: String::new(),
                                suggestion: Some(format!(
                                    "Add a range check: if ({} >= 0) before returning as unsigned",
                                    name
                                )),
                                requires_manual_review: None,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Check `unsigned int x = signed_var;` declarations.
    fn check_unsigned_init_from_signed(
        &self,
        decl_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(base) = Self::base_type_text(decl_node, source) else {
            return;
        };
        if self.type_text_signedness(&base) != Some(Signedness::Unsigned) {
            return;
        }

        // Look for init_declarator with an identifier initializer
        let mut cursor = decl_node.walk();
        for child in decl_node.children(&mut cursor) {
            if child.kind() != "init_declarator" {
                continue;
            }
            // `unsigned int *p = q;` initializes a pointer, not an unsigned
            // object -- the declaration's base type is only the object's
            // type when this declarator adds no indirection.
            if child
                .child_by_field_name("declarator")
                .is_none_or(|d| d.kind() != "identifier")
            {
                continue;
            }
            if let Some(value) = child.child_by_field_name("value") {
                if value.kind() == "identifier" && self.is_signed_integer_here(&value, source) {
                    let init_name = get_node_text(&value, source).to_string();
                    if !self.has_non_negative_guard(decl_node, &init_name, source) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: format!(
                                "Signed variable '{}' assigned to unsigned without range check",
                                init_name
                            ),
                            severity: self.severity(),
                            line: decl_node.start_position().row + 1,
                            column: decl_node.start_position().column + 1,
                            file_path: String::new(),
                            suggestion: Some(format!(
                                "Add a range check: if ({} >= 0) before assigning to unsigned",
                                init_name
                            )),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }
    }

    /// Check `unsigned_var = signed_var;` assignments.
    fn check_unsigned_assign_from_signed(
        &self,
        assign_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Compound assignments (`+=`, `-=`, `/=`) are not the shape this check
        // reports or the shape its suggestion fixes: `pos += ret` over a `char *`
        // is pointer arithmetic, and `len -= n` is accumulation whose whole point
        // is the operand's sign. Only a plain copy converts a signed value into an
        // unsigned object the way the message describes. (`&=`/`|=`/`^=` are
        // already the bitwise check's business, not this one's.)
        match assign_node.child_by_field_name("operator") {
            Some(op) if get_node_text(&op, source) == "=" => {}
            _ => return,
        }

        let (Some(left), Some(right)) = (
            assign_node.child_by_field_name("left"),
            assign_node.child_by_field_name("right"),
        ) else {
            return;
        };
        if right.kind() != "identifier" || !self.is_signed_integer_here(&right, source) {
            return;
        }
        let right_name = get_node_text(&right, source).to_string();

        // A signed declaration says a sign CAN be there; require VRA evidence
        // that one actually is before reporting it lost -- see the note on
        // `right_operand_may_be_negative`.
        if !self.right_operand_may_be_negative(&right, source, &right_name) {
            return;
        }

        // The destination must be shown unsigned, not merely not-known-signed.
        if !self.lvalue_is_unsigned_integer(&left, source) {
            return;
        }

        if !self.has_non_negative_guard(assign_node, &right_name, source) {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                message: format!(
                    "Signed variable '{}' assigned to unsigned variable without range check",
                    right_name
                ),
                severity: self.severity(),
                line: assign_node.start_position().row + 1,
                column: assign_node.start_position().column + 1,
                file_path: String::new(),
                suggestion: Some(format!(
                    "Add a range check: if ({} >= 0) before assigning to unsigned",
                    right_name
                )),
                requires_manual_review: None,
            });
        }
    }

    /// Check if the node is inside a guard like `if (var >= 0)` or `if (var > 0)`.
    fn has_non_negative_guard(&self, node: &Node, var_name: &str, source: &str) -> bool {
        let mut current = node.parent();
        while let Some(ancestor) = current {
            if matches!(
                ancestor.kind(),
                "if_statement" | "while_statement" | "for_statement"
            ) {
                if let Some(condition) = ancestor.child_by_field_name("condition") {
                    let cond_text = get_node_text(&condition, source);
                    if cond_text.contains(var_name)
                        && (cond_text.contains(">= 0")
                            || cond_text.contains("> 0")
                            || cond_text.contains("!= -")
                            || cond_text.contains(">= 0"))
                    {
                        return true;
                    }
                }
            }
            if ancestor.kind() == "function_definition" {
                break;
            }
            current = ancestor.parent();
        }
        false
    }

    /// Positive VRA evidence that the assigned-from variable can actually hold
    /// a negative value at this assignment.
    ///
    /// Without it this check fired on every `struct_field = some_int`, because
    /// "the name was declared signed somewhere in the file" says nothing about
    /// whether a sign is there to be lost. A length, a count, an enumerator and
    /// a return value already checked for `< 0` all reach here looking exactly
    /// like a value that could be negative.
    fn right_operand_may_be_negative(&self, right: &Node, source: &str, name: &str) -> bool {
        vra_access::has_negative_value_evidence(
            &self.function_cfgs.borrow(),
            &self.vra_results.borrow(),
            right,
            source,
            &MacroConstantMap::new(),
            name,
        )
    }
}
