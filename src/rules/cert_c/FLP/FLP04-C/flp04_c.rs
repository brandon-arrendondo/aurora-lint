// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! FLP04-C: Check floating-point inputs for exceptional values
//!
//! This rule detects floating-point inputs (from scanf, fscanf, etc.) that are not
//! validated for exceptional values (NaN, infinity) before use. Exceptional values can
//! corrupt data and propagate through calculations, destroying program integrity.
//!
//! ## Key Violations:
//! - Using scanf("%f", &var) without checking isinf(var) or isnan(var)
//! - Using float inputs in calculations before validation
//! - Missing validation checks after floating-point input operations
//!
//! ## Noncompliant Code Example:
//! ```c
//! float val;
//! scanf("%f", &val);
//! currentBalance += val;  // VIOLATION: No validation
//! ```
//!
//! ## Compliant Solution:
//! ```c
//! float val;
//! scanf("%f", &val);
//! if (isinf(val) || isnan(val)) {
//!     // Handle error
//! }
//! currentBalance += val;  // OK: Validated
//! ```
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/FLP04-C.+Check+floating-point+inputs+for+exceptional+values

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

#[derive(Debug)]
pub struct Flp04C;

impl Flp04C {
    pub fn new() -> Self {
        Flp04C
    }

    /// Check if a format string contains floating-point specifiers
    fn has_float_format_specifier(&self, format_str: &str) -> bool {
        // Remove escaped characters and string quotes
        let cleaned = format_str.replace("\\\"", "").replace("\"", "");

        // Look for float format specifiers: %f, %lf, %e, %E, %g, %G, %a, %A
        let float_specs = [
            "%f", "%lf", "%e", "%E", "%g", "%G", "%a", "%A", "%Lf", "%Le", "%LE", "%Lg", "%LG",
            "%La", "%LA",
        ];

        for spec in &float_specs {
            if cleaned.contains(spec) {
                return true;
            }
        }

        false
    }

    /// Check if a function call is a floating-point input function
    fn is_float_input_function(&self, node: &Node, source: &str) -> Option<Vec<String>> {
        if node.kind() != "call_expression" {
            return None;
        }

        // Get function name
        let func_name = if let Some(func_node) = node.child_by_field_name("function") {
            get_node_text(&func_node, source)
        } else {
            return None;
        };

        // Check if it's scanf, fscanf, sscanf, etc.
        let input_funcs = ["scanf", "fscanf", "sscanf", "vfscanf", "vscanf", "vsscanf"];
        if !input_funcs.contains(&func_name) {
            return None;
        }

        // Get arguments
        let args = node.child_by_field_name("arguments")?;

        // Collect all arguments (skip commas and parentheses)
        let mut all_args = Vec::new();
        let mut cursor = args.walk();
        for child in args.children(&mut cursor) {
            if child.is_named() && child.kind() != "," {
                all_args.push(child);
            }
        }

        if all_args.is_empty() {
            return None;
        }

        // Determine format string index (0 for scanf, 1 for fscanf)
        let format_index = if func_name == "fscanf" || func_name == "vfscanf" {
            1
        } else {
            0
        };

        if all_args.len() <= format_index {
            return None;
        }

        // Get format string
        let format_arg = all_args[format_index];
        let format_string = get_node_text(&format_arg, source);

        // Check if format has float specifiers
        if !self.has_float_format_specifier(&format_string) {
            return None;
        }

        // Extract variable names from pointer expressions after format string
        let mut float_vars = Vec::new();
        for arg in all_args.iter().skip(format_index + 1) {
            let arg = *arg;
            if arg.kind() == "pointer_expression" {
                if let Some(var_node) = arg.child_by_field_name("argument") {
                    let var_name = get_node_text(&var_node, source).to_string();
                    float_vars.push(var_name);
                }
            }
        }

        if !float_vars.is_empty() {
            Some(float_vars)
        } else {
            None
        }
    }

    /// Check if a node contains validation for a variable (isinf or isnan)
    fn has_validation_check(&self, node: &Node, source: &str, var_name: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            let text = get_node_text(&n, source);

            // Check for isinf(var) or isnan(var) patterns
            if (text.contains("isinf") || text.contains("isnan")) && text.contains(var_name) {
                return true;
            }

            // Check for fpclassify(var) patterns
            text.contains("fpclassify") && text.contains(var_name)
        })
        .is_some()
    }

    /// Check if a variable is used in an expression
    fn is_var_used(&self, node: &Node, source: &str, var_name: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            n.kind() == "identifier" && get_node_text(&n, source) == var_name
        })
        .is_some()
    }

    /// Check a function for unvalidated float inputs
    fn check_function(&self, func_node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Track float input variables and their validation status
        let mut float_inputs: HashMap<String, (usize, usize)> = HashMap::new(); // var -> (line, col)
        let mut validated_vars: HashSet<String> = HashSet::new();

        // First pass: find all float inputs
        self.collect_float_inputs(func_node, source, &mut float_inputs);

        // Second pass: find validation checks
        self.collect_validations(func_node, source, &float_inputs, &mut validated_vars);

        // Third pass: check for usage before validation
        for (var_name, (line, col)) in &float_inputs {
            if !validated_vars.contains(var_name) {
                // Check if variable is actually used
                if self.is_var_used(func_node, source, var_name) {
                    violations.push(RuleViolation {
                        rule_id: "FLP04-C".to_string(),
                        severity: Severity::Medium,
                        line: *line,
                        column: *col,
                        message: format!(
                            "Floating-point input variable '{}' is not validated for exceptional values (NaN, infinity) before use",
                            var_name
                        ),
                        file_path: String::new(),
                        suggestion: Some(
                            format!("Add validation: if (isinf({0}) || isnan({0})) {{ /* handle error */ }}", var_name)
                        ),
                        requires_manual_review: Some(false),
                    });
                }
            }
        }
    }

    /// Collect float input variables
    fn collect_float_inputs(
        &self,
        node: &Node,
        source: &str,
        float_inputs: &mut HashMap<String, (usize, usize)>,
    ) {
        for n in query::find_descendants(*node, |_| true) {
            if let Some(vars) = self.is_float_input_function(&n, source) {
                for var in vars {
                    float_inputs.insert(
                        var,
                        (n.start_position().row + 1, n.start_position().column + 1),
                    );
                }
            }
        }
    }

    /// Collect variables that have been validated
    fn collect_validations(
        &self,
        node: &Node,
        source: &str,
        float_inputs: &HashMap<String, (usize, usize)>,
        validated_vars: &mut HashSet<String>,
    ) {
        for var_name in float_inputs.keys() {
            if self.has_validation_check(node, source, var_name) {
                validated_vars.insert(var_name.clone());
            }
        }
    }

    /// Traverse the AST looking for functions
    fn traverse(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function(&n, source, violations);
        }
    }
}

impl CertRule for Flp04C {
    fn rule_id(&self) -> &'static str {
        "FLP04-C"
    }

    fn description(&self) -> &'static str {
        "Check floating-point inputs for exceptional values"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "FLP04-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
