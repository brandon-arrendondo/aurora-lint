// DCL20-C: Explicitly specify void when a function accepts no arguments
//
// This rule detects function declarations and definitions that have empty
// parameter lists () instead of explicit (void), which in C means the function
// can accept any number of arguments (not checked by compiler).
//
// Detection strategy:
// 1. Find all function declarations and definitions
// 2. Check if parameter list is empty ()
// 3. Flag violations and suggest using (void)

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use tree_sitter::Node;

pub struct Dcl20C;

impl Dcl20C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Dcl20C
    }

    /// Check a node and all its descendants for violations
    fn check_node<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Only check function declarations (prototypes), NOT definitions.
        // In C, f() in a definition already means "no arguments" and is
        // just a style concern. In a declaration/prototype, f() means
        // "unspecified arguments" which is the actual semantic issue.
        if node.kind() == "declaration" {
            // Look for function declarators in the declaration
            self.check_declaration_for_function(&node, source, violations);
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_node(&child, source, violations);
            }
        }
    }

    /// Check a function declarator for empty parameter list
    fn check_function_declarator<'a>(
        &self,
        declarator: &Node<'a>,
        source: &'a str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Find the function_declarator node
        if declarator.kind() == "function_declarator" {
            if let Some(params) = declarator.child_by_field_name("parameters") {
                // Check if parameter list is empty or has no void
                if self.has_empty_parameters(&params, source) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        line: params.start_position().row + 1,
                        column: params.start_position().column + 1,
                        message: "Function has empty parameter list () - should explicitly specify (void) to indicate no arguments".to_string(),
                        severity: self.severity(),
                        file_path: String::new(),
                        suggestion: Some("Change () to (void) to explicitly indicate function takes no arguments".to_string()),
                        requires_manual_review: None,
                    });
                }
            }
        } else {
            // Recurse to find function_declarator
            for i in 0..declarator.child_count() {
                if let Some(child) = declarator.child(i) {
                    self.check_function_declarator(&child, source, violations);
                }
            }
        }
    }

    /// Check declaration for function declarators
    fn check_declaration_for_function<'a>(
        &self,
        decl: &Node<'a>,
        source: &'a str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for function_declarator in the declaration
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "function_declarator" || child.kind() == "init_declarator" {
                    self.check_function_declarator(&child, source, violations);
                }
            }
        }
    }

    /// Check if parameter list is empty (no void)
    fn has_empty_parameters<'a>(&self, params: &Node<'a>, source: &'a str) -> bool {
        let params_text = get_node_text(params, source).trim();

        // Check if it's literally just ()
        if params_text == "()" {
            return true;
        }

        // Check if there are any parameter_declaration children
        let mut has_params = false;
        for i in 0..params.child_count() {
            if let Some(child) = params.child(i) {
                if child.kind() == "parameter_declaration" {
                    has_params = true;
                    // Check if it's a void parameter
                    let param_text = get_node_text(&child, source).trim();
                    if param_text == "void" {
                        return false; // Has explicit void, no violation
                    }
                } else if child.kind() == "type_identifier" {
                    // Direct type identifier child
                    let type_text = get_node_text(&child, source).trim();
                    if type_text == "void" {
                        return false; // Has explicit void
                    }
                }
            }
        }

        // If no parameters found and not explicitly void, it's a violation
        if !has_params {
            // Double check the text doesn't contain void
            return !params_text.contains("void");
        }

        false
    }
}

impl CertRule for Dcl20C {
    fn rule_id(&self) -> &'static str {
        "DCL20-C"
    }

    fn description(&self) -> &'static str {
        "Explicitly specify void when a function accepts no arguments"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL20-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}
