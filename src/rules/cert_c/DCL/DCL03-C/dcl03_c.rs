use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Dcl03C;

impl CertRule for Dcl03C {
    fn rule_id(&self) -> &'static str {
        "DCL03-C"
    }

    fn description(&self) -> &'static str {
        "Use a static assertion to test the value of a constant expression"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL03-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        query::find_descendants_of_kind(*node, "call_expression")
            .into_iter()
            .filter_map(|call| self.check_call_expression(call, source))
            .collect()
    }
}

impl Dcl03C {
    fn check_call_expression(&self, node: Node, source: &str) -> Option<RuleViolation> {
        let function = node.child_by_field_name("function")?;
        let func_text = ast_utils::get_node_text(&function, source);

        // Check if this is an assert() call
        if func_text != "assert" {
            return None;
        }

        // Get the arguments
        let arguments = node.child_by_field_name("arguments")?;
        // Check if the argument is a constant expression
        if !is_constant_expression(&arguments, source) {
            return None;
        }

        let start_point = node.start_position();
        Some(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::Low,
            message: "Runtime assert() used with constant expression; consider using static_assert() instead".to_string(),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(
                "Replace assert() with static_assert() to evaluate at compile time"
                    .to_string(),
            ),
            ..Default::default()
        })
    }
}

/// Check if an expression is a constant expression that can be evaluated at compile time
///
/// This includes:
/// - sizeof expressions
/// - Numeric literals
/// - Binary operations involving only constant expressions
/// - Comparisons involving only constant expressions
fn is_constant_expression(node: &Node, source: &str) -> bool {
    // Get the first actual argument (skip punctuation)
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                return is_constant_expr_recursive(&child, source);
            }
        }
    }
    false
}

/// Recursively check if an expression tree contains only constant expressions
fn is_constant_expr_recursive(node: &Node, source: &str) -> bool {
    match node.kind() {
        // sizeof is always a compile-time constant
        "sizeof_expression" => true,

        // Numeric literals are constants
        "number_literal" => true,

        // Character literals are constants
        "char_literal" => true,

        // Binary expressions are constant if both sides are constant
        "binary_expression" => {
            let mut has_constant_operands = true;

            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    // Skip operators
                    if !is_operator(&child, source) {
                        if !is_constant_expr_recursive(&child, source) {
                            has_constant_operands = false;
                            break;
                        }
                    }
                }
            }

            has_constant_operands
        }

        // Parenthesized expressions - check the inner expression
        "parenthesized_expression" => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() != "(" && child.kind() != ")" {
                        return is_constant_expr_recursive(&child, source);
                    }
                }
            }
            false
        }

        // Type identifiers are part of sizeof/constant expressions
        "type_identifier" | "primitive_type" | "sized_type_specifier" | "struct_specifier" => true,

        // Field expressions (like struct.field) in sizeof context
        "field_expression" => {
            // In context of sizeof, this is constant
            // Check if parent is sizeof_expression
            if let Some(parent) = node.parent() {
                if parent.kind() == "sizeof_expression" {
                    return true;
                }
            }
            false
        }

        // Cast expressions - check if the inner expression is constant
        "cast_expression" => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() != "("
                        && child.kind() != ")"
                        && child.kind() != "type_descriptor"
                    {
                        return is_constant_expr_recursive(&child, source);
                    }
                }
            }
            false
        }

        // Unary expressions (like +, -, !) - check the operand
        "unary_expression" => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if !is_operator(&child, source) {
                        return is_constant_expr_recursive(&child, source);
                    }
                }
            }
            false
        }

        // Identifiers might be constants (macros, enums, const vars)
        // For simplicity, we'll consider them as potentially non-constant
        // unless they're part of sizeof
        "identifier" => {
            let text = ast_utils::get_node_text(node, source);
            // ALL_CAPS names are conventionally macro constants
            ast_utils::is_likely_macro_constant(text)
        }

        _ => false,
    }
}

/// Check if a node is an operator
fn is_operator(node: &Node, source: &str) -> bool {
    let text = ast_utils::get_node_text(node, source);
    matches!(
        text,
        "+" | "-"
            | "*"
            | "/"
            | "%"
            | "=="
            | "!="
            | "<"
            | ">"
            | "<="
            | ">="
            | "&&"
            | "||"
            | "&"
            | "|"
            | "^"
            | "<<"
            | ">>"
            | "!"
            | "~"
    )
}
