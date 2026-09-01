//! FLP05-C: Do not use denormalized numbers
//!
//! This rule detects operations involving denormalized floating-point constants
//! with float types. Denormalized numbers are extremely small values that lose
//! precision because mantissa bits are used to extend the exponent range.
//!
//! For IEEE 754 floats, values smaller than approximately 1.175e-38 are
//! denormalized and lose precision.
//!
//! VIOLATIONS:
//! - float variable multiplied/divided by denormalized constant (e.g., 7e-45)
//! - float variable assigned a denormalized constant
//!
//! COMPLIANT:
//! - Using double instead of float for operations with very small numbers
//! - Using float with normal-range values only

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Flp05C;

// Minimum normalized float value (approximately 1.175e-38)
// Values below this are denormalized for float type
const FLOAT_MIN_NORMALIZED: f64 = 1.175e-38;

impl CertRule for Flp05C {
    fn rule_id(&self) -> &'static str {
        "FLP05-C"
    }

    fn description(&self) -> &'static str {
        "Do not use denormalized numbers"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "FLP05-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        // Each function gets its own `var_types` scope: a same-named
        // variable in a different function is a different object, and
        // `process_declaration` doesn't even see parameter declarations
        // (only `declaration`-kind local vars), so a stale entry from one
        // function's local (e.g. `float x`) could otherwise leak into
        // another function's unrelated same-named parameter or local
        // (task 418). Scope the whole-source walk per `function_definition`,
        // mirroring EXP39-C/STR32-C's per-function reset pattern.
        let functions = query::find_descendants_of_kind(*node, "function_definition");
        if functions.is_empty() {
            let mut var_types: HashMap<String, String> = HashMap::new();
            self.check_node(node, source, &mut violations, &mut var_types);
        } else {
            for func in functions {
                let mut var_types: HashMap<String, String> = HashMap::new();
                self.check_node(&func, source, &mut violations, &mut var_types);
            }
        }
        violations
    }
}

impl Flp05C {
    fn check_node(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &mut HashMap<String, String>,
    ) {
        // Visit declarations, binary expressions, and init declarators in
        // document pre-order (same order the original recursive walk visited
        // them in), since var_types is built incrementally as we go.
        for n in query::find_descendants_of_kinds(
            *node,
            &["declaration", "binary_expression", "init_declarator"],
        ) {
            match n.kind() {
                // Track variable declarations to know their types
                "declaration" => self.process_declaration(&n, source, var_types),
                // Look for binary expressions involving potential denormalized values
                "binary_expression" => {
                    self.check_binary_expression(&n, source, violations, var_types)
                }
                // Look for assignments of denormalized values to float
                "init_declarator" => self.check_init_declarator(&n, source, violations),
                _ => unreachable!(),
            }
        }
    }

    fn process_declaration(
        &self,
        node: &Node,
        source: &str,
        var_types: &mut HashMap<String, String>,
    ) {
        // Extract type from declaration
        if let Some(type_node) = node.child_by_field_name("type") {
            let type_text = get_node_text(&type_node, source).to_string();

            // Find all declarators in the declaration
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "init_declarator" || child.kind() == "identifier" {
                        // Get the variable name
                        let var_name = if child.kind() == "init_declarator" {
                            // Look for identifier in init_declarator
                            child
                                .child_by_field_name("declarator")
                                .map(|d| get_node_text(&d, source).to_string())
                                .unwrap_or_default()
                        } else {
                            get_node_text(&child, source).to_string()
                        };

                        if !var_name.is_empty() {
                            var_types.insert(var_name, type_text.clone());
                        }
                    }
                }
            }
        }
    }

    fn check_binary_expression(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, String>,
    ) {
        // Check for multiplication or division with denormalized constants
        let operator = node.child_by_field_name("operator").or_else(|| {
            // Fallback: look for operator in children
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    let kind = child.kind();
                    if kind == "*" || kind == "/" {
                        return Some(child);
                    }
                }
            }
            None
        });

        if let Some(op_node) = operator {
            let op = get_node_text(&op_node, source);
            if op == "*" || op == "/" {
                // Check both operands for denormalized constants
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    // Check if one operand is a float variable and the other is denormalized
                    let left_is_float = self.is_float_variable(&left, source, var_types);
                    let right_is_float = self.is_float_variable(&right, source, var_types);
                    let left_denorm = self.get_denormalized_value(&left, source);
                    let right_denorm = self.get_denormalized_value(&right, source);

                    if left_is_float && right_denorm.is_some() {
                        let pos = right.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Low,
                            message: format!(
                                "Float variable operated with denormalized constant {}; this can cause precision loss",
                                get_node_text(&right, source)
                            ),
                            file_path: String::new(),
                            line: pos.row + 1,
                            column: pos.column + 1,
                            suggestion: Some(
                                "Consider using double instead of float for operations involving very small numbers".to_string(),
                            ),
                            ..Default::default()
                        });
                    } else if right_is_float && left_denorm.is_some() {
                        let pos = left.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Low,
                            message: format!(
                                "Float variable operated with denormalized constant {}; this can cause precision loss",
                                get_node_text(&left, source)
                            ),
                            file_path: String::new(),
                            line: pos.row + 1,
                            column: pos.column + 1,
                            suggestion: Some(
                                "Consider using double instead of float for operations involving very small numbers".to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    fn check_init_declarator(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // For init_declarator, check if it's a float type being initialized with denormalized value
        // Look for parent declaration to get type
        if let Some(parent) = node.parent() {
            if parent.kind() == "declaration" {
                if let Some(type_node) = parent.child_by_field_name("type") {
                    let type_text = get_node_text(&type_node, source);
                    if type_text == "float" {
                        // Check the initializer value
                        if let Some(value_node) = node.child_by_field_name("value") {
                            if self.get_denormalized_value(&value_node, source).is_some() {
                                let pos = value_node.start_position();
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Low,
                                    message: format!(
                                        "Float initialized with denormalized value {}; this can cause precision loss",
                                        get_node_text(&value_node, source)
                                    ),
                                    file_path: String::new(),
                                    line: pos.row + 1,
                                    column: pos.column + 1,
                                    suggestion: Some(
                                        "Consider using double instead of float for very small values".to_string(),
                                    ),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn is_float_variable(
        &self,
        node: &Node,
        source: &str,
        var_types: &HashMap<String, String>,
    ) -> bool {
        if node.kind() == "identifier" {
            let var_name = get_node_text(node, source);
            // Check if this variable was declared as float
            if let Some(var_type) = var_types.get(var_name) {
                return var_type == "float";
            }
        }
        false
    }

    fn get_denormalized_value(&self, node: &Node, source: &str) -> Option<f64> {
        let text = get_node_text(node, source);

        // Parse the numeric value
        if node.kind() == "number_literal" {
            // Handle scientific notation like 7e-45
            if let Ok(val) = text.parse::<f64>() {
                // Check if it's in the denormalized range for float
                if val.abs() > 0.0 && val.abs() < FLOAT_MIN_NORMALIZED {
                    return Some(val);
                }
            }
        }

        None
    }
}
