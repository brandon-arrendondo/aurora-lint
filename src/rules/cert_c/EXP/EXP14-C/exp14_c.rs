//! EXP14-C: Beware of integer promotion when performing bitwise operations on integer types smaller than int
//!
//! When performing bitwise operations on types smaller than int (e.g., char, uint8_t, int8_t),
//! the C standard automatically promotes these values to int. This can cause unexpected results
//! because the bitwise operation is performed on the promoted (wider) value.
//!
//! ## Examples:
//!
//! **Non-compliant (missing explicit cast):**
//! ```c
//! uint8_t port = 0x5a;
//! uint8_t result_8 = (~port) >> 4;  // Violates EXP14-C - implicit promotion
//! ```
//!
//! **Compliant (explicit cast):**
//! ```c
//! uint8_t port = 0x5a;
//! uint8_t result_8 = (uint8_t)(~port) >> 4;  // Explicit cast prevents issues
//! ```
//!
//! ## Detection Strategy:
//! - Identify assignment expressions where small integer types are assigned
//! - Check if the RHS contains bitwise operations on small types
//! - Resolve the operand's declared type (following typedefs project-wide)
//!   and only proceed when it's genuinely narrower than `int` -- a `~`/`<<`
//!   on an `int`-or-wider operand (or an unresolvable macro/enum name,
//!   which is `int` by default) is never at risk from promotion
//! - Verify if there's an explicit cast to the target type
//! - Flag violations where no explicit cast wraps the bitwise operation

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use crate::utility::cert_c::ast_utils::resolve_field_expression_type;
use crate::utility::cert_c::overflow_helpers::resolve_typedef_chain;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashMap;
use tree_sitter::Node;

/// Bit width at/above which integer promotion to `int` is a no-op (or the
/// operand is already wider than `int`), so no promotion hazard exists.
const INT_WIDTH: u32 = 32;

#[derive(Default)]
pub struct Exp14C {
    /// Cross-file typedef chain (`ProjectContext::typedef_types`), needed to
    /// resolve a project-local narrow-width spelling (hostap's `u8`/`u16`,
    /// kernel-style typedefs) to a builtin width the same way a real scan
    /// would see it, rather than only recognizing `uint8_t`/`uint16_t` by
    /// literal spelling.
    typedef_types: RefCell<HashMap<String, String>>,
    /// Cross-file struct field types (`ProjectContext::struct_field_types`),
    /// needed to resolve a narrow struct-member operand (`s->flags`) --
    /// otherwise a bitmask/capability field, which is how a narrow type
    /// most often appears in real code, never resolves at all.
    struct_field_types: RefCell<HashMap<String, HashMap<String, String>>>,
}

impl CertRule for Exp14C {
    fn rule_id(&self) -> &'static str {
        "EXP14-C"
    }

    fn description(&self) -> &'static str {
        "Beware of integer promotion when performing bitwise operations on integer types smaller than int"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP14-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.typedef_types.borrow_mut() = context.typedef_types.clone();
        *self.struct_field_types.borrow_mut() = context.struct_field_types.clone();
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Exp14C {
    /// Recursively checks nodes for bitwise operations on small integer types without explicit casts
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            match n.kind() {
                "assignment_expression" => self.check_assignment(&n, source, violations),
                "init_declarator" => self.check_init_declarator(&n, source, violations),
                _ => {}
            }
        }
    }

    /// Checks an assignment expression for bitwise operations on small types
    fn check_assignment(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(right) = node.child_by_field_name("right") {
            self.check_bitwise_expression(&right, source, violations);
        }
    }

    /// Checks an init declarator (variable declaration with initialization)
    fn check_init_declarator(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(value) = node.child_by_field_name("value") {
            self.check_bitwise_expression(&value, source, violations);
        }
    }

    /// Checks if an expression contains bitwise operations on small types without explicit casts
    fn check_bitwise_expression(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // If this node is a cast_expression, don't check inside it - the cast handles promotion
        if node.kind() == "cast_expression" {
            return;
        }

        match node.kind() {
            "unary_expression" => {
                // Check for bitwise NOT (~)
                if let Some(operator) = node.child_by_field_name("operator") {
                    let op_text = ast_utils::get_node_text(&operator, source);
                    if op_text == "~" {
                        // Only a genuinely narrower-than-int operand is at risk:
                        // promoting int-or-wider changes nothing observable.
                        let is_narrow = node
                            .child_by_field_name("argument")
                            .and_then(|arg| self.resolve_operand_width(&arg, source, 0))
                            .is_some_and(|width| width < INT_WIDTH);

                        if is_narrow && !is_wrapped_in_cast(node) {
                            violations.push(RuleViolation {
                                rule_id: "EXP14-C".to_string(),
                                severity: Severity::Medium,
                                message: "Bitwise operation on type smaller than int may cause unexpected integer promotion. Use explicit cast to control promotion behavior.".to_string(),
                                file_path: String::new(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                suggestion: Some(
                                    "Wrap the bitwise operation with an explicit cast: (uint8_t)(~value)".to_string()
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
            "binary_expression" => {
                // Check for bitwise operators that are genuinely risky after promotion.
                // &, |, ^, >> are safe: promotion widens but the result, when truncated
                // back to the small type, is identical to the non-promoted result.
                // Only ~ (unary, handled above) and << are risky: ~ sign-extends the
                // upper bits, and << can produce a value wider than the original type.
                if let Some(operator) = node.child_by_field_name("operator") {
                    let op_text = ast_utils::get_node_text(&operator, source);
                    if matches!(op_text, "<<") {
                        let left = node.child_by_field_name("left");
                        // Check if left operand has an explicit cast
                        let left_has_cast =
                            left.as_ref().is_some_and(|l| l.kind() == "cast_expression");

                        // Only the shifted value's width matters -- the shift
                        // count (the right operand) has no representation-
                        // dependent risk regardless of its own type.
                        let is_narrow = left
                            .as_ref()
                            .and_then(|l| self.resolve_operand_width(l, source, 0))
                            .is_some_and(|width| width < INT_WIDTH);

                        if is_narrow && !left_has_cast && !is_wrapped_in_cast(node) {
                            violations.push(RuleViolation {
                                rule_id: "EXP14-C".to_string(),
                                severity: Severity::Medium,
                                message: format!(
                                    "Bitwise operation '{}' on type smaller than int may cause unexpected integer promotion. Use explicit cast to control promotion behavior.",
                                    op_text
                                ),
                                file_path: String::new(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                suggestion: Some(
                                    "Wrap the bitwise operation with an explicit cast: (uint8_t)(value & mask)".to_string()
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        // Recursively check children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.check_bitwise_expression(&child, source, violations);
        }
    }

    /// Declared width (in bits) of the integer object `node` denotes, after
    /// peeling `unwrap` pointer/array levels (`p[i]`, `*p`). `None` when the
    /// type can't be resolved (unknown typedef, macro-substituted name with
    /// no declaration, struct/pointer type, ...) -- deliberately NOT treated
    /// as "narrow": the rule needs positive proof of a sub-int width before
    /// flagging, matching CERT's own premise that the hazard exists only for
    /// a genuinely narrower-than-int operand.
    fn resolve_operand_width(&self, node: &Node, source: &str, unwrap: usize) -> Option<u32> {
        match node.kind() {
            "parenthesized_expression" => {
                self.resolve_operand_width(&node.named_child(0)?, source, unwrap)
            }
            "cast_expression" => {
                let ty = node.child_by_field_name("type")?;
                let text = ast_utils::get_node_text(&ty, source);
                if text.contains('*') {
                    return None;
                }
                self.width_of_type_text(text)
            }
            "number_literal" => {
                // An integer constant is `int` unless a `u`/`l`/`ll` suffix
                // says otherwise -- never narrower than int either way.
                let text = ast_utils::get_node_text(node, source);
                let suffix: String = text
                    .chars()
                    .rev()
                    .take_while(|c| matches!(c, 'u' | 'U' | 'l' | 'L'))
                    .collect();
                if suffix.contains(['l', 'L']) {
                    Some(64)
                } else {
                    Some(INT_WIDTH)
                }
            }
            "identifier" => {
                let name = ast_utils::get_node_text(node, source);
                let (decl, mut declarator) =
                    ast_utils::resolve_identifier_declarator(node, name, source)?;
                for _ in 0..unwrap {
                    if !matches!(declarator.kind(), "pointer_declarator" | "array_declarator") {
                        return None;
                    }
                    declarator = declarator.child_by_field_name("declarator")?;
                }
                if declarator.kind() != "identifier" {
                    return None;
                }
                self.width_of_type_text(&ast_utils::declaration_type_text(&decl, source))
            }
            "subscript_expression" => {
                let arg = node.child_by_field_name("argument")?;
                self.resolve_operand_width(&arg, source, unwrap + 1)
            }
            "pointer_expression" if ast_utils::is_dereference_expression(node, source) => {
                let arg = node.child_by_field_name("argument")?;
                self.resolve_operand_width(&arg, source, unwrap + 1)
            }
            "field_expression" if unwrap <= 1 => {
                let field_type = self.field_type_text(node, source)?;
                // unwrap==1 (one subscript into the field, `s->arr[i]`) is
                // only safe when the field itself is an array: the recorded
                // type is already the element type (struct_field_types
                // drops array declarators the same way declaration_type_text
                // does for a plain variable), so no further peeling is
                // needed -- but a pointer-typed field (`s->ptr[i]`) would
                // need one pointer level stripped, which isn't derivable
                // from the field's type text alone, so decline rather than
                // guess.
                if unwrap == 1 && field_type.contains('*') {
                    None
                } else {
                    self.width_of_type_text(&field_type)
                }
            }
            _ => None,
        }
    }

    /// The prescan-recorded type of the field `expr` (`s->count`, `a.b->c`)
    /// denotes, resolved from the base identifier's declaration in scope --
    /// same composition INT16-C's `field_type_text` uses, a one-entry type
    /// map built from the scope-aware declarator lookup rather than a
    /// file-wide flat map, which the capability catalog flags as
    /// mis-attributing same-named locals across functions.
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
        let base_name = ast_utils::get_node_text(&base, source);
        let (decl, declarator) =
            ast_utils::resolve_identifier_declarator(&base, base_name, source)?;
        let mut base_type = ast_utils::declaration_type_text(&decl, source);
        let mut d = declarator;
        while d.kind() == "pointer_declarator" {
            base_type.push_str(" *");
            d = d.child_by_field_name("declarator")?;
        }
        let type_map = HashMap::from([(base_name.to_string(), base_type)]);
        resolve_field_expression_type(expr, source, &type_map, &self.struct_field_types.borrow())
    }

    /// Width of a declared type spelling, qualifiers dropped and typedefs
    /// followed project-wide (`u8`/`u16`-style project aliases included).
    fn width_of_type_text(&self, text: &str) -> Option<u32> {
        let base = text
            .split_whitespace()
            .filter(|t| {
                !matches!(
                    *t,
                    "const"
                        | "volatile"
                        | "static"
                        | "extern"
                        | "register"
                        | "_Atomic"
                        | "restrict"
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        let resolved = resolve_typedef_chain(&base, &self.typedef_types.borrow());
        ast_utils::integer_type_width(&resolved)
    }
}

/// Checks if a node is wrapped in a cast expression
fn is_wrapped_in_cast(node: &Node) -> bool {
    if let Some(parent) = node.parent() {
        // Check if parent is a cast_expression
        if parent.kind() == "cast_expression" {
            // Verify this node is the value being cast
            if let Some(value) = parent.child_by_field_name("value") {
                if value.id() == node.id() {
                    return true;
                }
            }
        }

        // Check if parent is a parenthesized expression that's inside a cast
        if parent.kind() == "parenthesized_expression" {
            return is_wrapped_in_cast(&parent);
        }
    }
    false
}
