//! INT13-C: Use bitwise operators only on unsigned operands
//!
//! Bitwise operations on signed integers can produce implementation-defined
//! or undefined behavior. Using bitwise operators on unsigned types ensures
//! predictable results across platforms.
//!
//! ## Violations:
//! - int x = ...; x << 2;    // Bitwise shift on signed int
//! - signed int y; y & mask; // Bitwise AND on signed operand
//!
//! ## Compliant:
//! - unsigned int x = ...; x << 2; // Bitwise shift on unsigned

use std::collections::HashMap;
use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;

pub struct Int13C;

impl CertRule for Int13C {
    fn rule_id(&self) -> &'static str {
        "INT13-C"
    }

    fn description(&self) -> &'static str {
        "Use bitwise operators only on unsigned operands"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "INT13-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Each function gets its own `variables` scope: a same-named
        // variable in a different function is a different object, and
        // `collect_declarations` doesn't even see parameter declarations
        // (only `declaration`-kind locals), so a stale entry from one
        // function (e.g. a signed `int mask`) could leak into an unrelated
        // same-named variable in another function (e.g. an `unsigned int
        // mask` parameter) and misfire here (task 418). Scope both the
        // collection and the check per `function_definition`, mirroring
        // EXP39-C/STR32-C's per-function reset pattern.
        let functions = query::find_descendants_of_kind(*node, "function_definition");
        if functions.is_empty() {
            let mut variables: HashMap<String, String> = HashMap::new();
            self.collect_declarations(node, source, &mut variables);
            self.check_bitwise_operations(node, source, &variables, &mut violations);
        } else {
            for func in functions {
                let mut variables: HashMap<String, String> = HashMap::new();
                self.collect_declarations(&func, source, &mut variables);
                self.check_bitwise_operations(&func, source, &variables, &mut violations);
            }
        }

        violations
    }
}

impl Int13C {
    /// Collect variable declarations and their types
    fn collect_declarations(
        &self,
        node: &Node,
        source: &str,
        variables: &mut HashMap<String, String>,
    ) {
        for n in query::find_descendants_of_kind(*node, "declaration") {
            let decl_text = get_node_text(&n, source);

            // Extract type and variable name
            if let Some((var_type, var_name)) = self.parse_declaration(&decl_text) {
                variables.insert(var_name, var_type);
            }
        }
    }

    /// Parse declaration to extract type and variable name
    fn parse_declaration(&self, decl_text: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = decl_text.split_whitespace().collect();

        if parts.len() >= 2 {
            // Handle types like "int x", "unsigned int x", "signed int x"
            if parts.len() >= 3 && (parts[0] == "unsigned" || parts[0] == "signed") {
                // "unsigned int x" or "signed int x"
                let var_type = format!("{} {}", parts[0], parts[1]);
                let var_name = parts[2]
                    .trim_end_matches(';')
                    .trim_end_matches(',')
                    .split('=')
                    .next()?
                    .trim()
                    .to_string();
                return Some((var_type, var_name));
            } else {
                // Simple type like "int x" or "long x"
                let var_type = parts[0].to_string();
                let var_name = parts[1]
                    .trim_end_matches(';')
                    .trim_end_matches(',')
                    .split('=')
                    .next()?
                    .trim()
                    .to_string();
                return Some((var_type, var_name));
            }
        }

        None
    }

    /// Check bitwise operations for signed operands
    fn check_bitwise_operations(
        &self,
        node: &Node,
        source: &str,
        variables: &HashMap<String, String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for bitwise binary expressions (<<, >>, &, |, ^)
        if node.kind() == "binary_expression" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = get_node_text(&op, source);

                // Check for bitwise operators
                if matches!(op_text.trim(), "<<" | ">>" | "&" | "|" | "^") {
                    // Get the operands
                    if let (Some(left), Some(right)) = (
                        node.child_by_field_name("left"),
                        node.child_by_field_name("right"),
                    ) {
                        // Check both operands for signed types
                        if let Some(violation) =
                            self.check_operand_type(&left, source, variables, op_text.trim())
                        {
                            violations.push(violation);
                            return; // Only report once per expression
                        }
                        if let Some(violation) =
                            self.check_operand_type(&right, source, variables, op_text.trim())
                        {
                            violations.push(violation);
                            return; // Only report once per expression
                        }
                    }
                }
            }
        }

        // Check for unary bitwise operations (~)
        if node.kind() == "unary_expression" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = get_node_text(&op, source);

                if op_text.trim() == "~" {
                    if let Some(operand) = node.child_by_field_name("argument") {
                        if let Some(violation) =
                            self.check_operand_type(&operand, source, variables, "~")
                        {
                            violations.push(violation);
                            return;
                        }
                    }
                }
            }
        }

        // Recursively check children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.check_bitwise_operations(&child, source, variables, violations);
        }
    }

    /// Check if an operand has a signed type
    fn check_operand_type(
        &self,
        operand: &Node,
        source: &str,
        variables: &HashMap<String, String>,
        operator: &str,
    ) -> Option<RuleViolation> {
        // Extract variable name from operand
        let var_name = self.extract_variable_name(operand, source)?;

        // Look up the variable type
        if let Some(var_type) = variables.get(&var_name) {
            // Check if it's a signed type
            if self.is_signed_type(var_type) {
                return Some(RuleViolation {
                    rule_id: "INT13-C".to_string(),
                    message: format!(
                        "Bitwise operator '{}' used on signed operand '{}' of type '{}'. Use unsigned types for bitwise operations",
                        operator, var_name, var_type
                    ),
                    severity: Severity::Medium,
                    line: operand.start_position().row + 1,
                    column: operand.start_position().column + 1,
                    file_path: String::new(),
                    suggestion: Some(format!(
                        "Change '{}' to an unsigned type (e.g., 'unsigned int' instead of 'int')",
                        var_name
                    )),
                    requires_manual_review: None,
                });
            }
        }

        None
    }

    /// Extract variable name from an expression node
    fn extract_variable_name(&self, node: &Node, source: &str) -> Option<String> {
        query::find_first_descendant(*node, |n| n.kind() == "identifier")
            .map(|n| get_node_text(&n, source).trim().to_string())
    }

    /// Check if a type is a signed integer type
    fn is_signed_type(&self, type_name: &str) -> bool {
        // Signed types are: int, short, long, long long, char (without unsigned keyword)
        // Also explicitly signed: signed int, signed short, signed long, signed char
        matches!(
            type_name,
            "int"
                | "short"
                | "long"
                | "long long"
                | "char"
                | "signed int"
                | "signed short"
                | "signed long"
                | "signed long long"
                | "signed char"
        )
    }
}
