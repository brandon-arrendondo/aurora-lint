//! DCL22-C: Use volatile for data that cannot be cached
//!
//! This rule detects variables that should be declared volatile but aren't.
//! Variables accessed in signal handlers or representing hardware/memory-mapped I/O
//! should be volatile to prevent unwanted compiler optimizations.
//!
//! VIOLATIONS:
//! - sig_atomic_t flag;              // Should be volatile sig_atomic_t
//! - int32_t bank[3]; modified around external function calls
//!
//! COMPLIANT:
//! - volatile sig_atomic_t flag;     // Correct for signal handler
//! - volatile int32_t bank[3];       // Correct for hardware register

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Dcl22C;

impl CertRule for Dcl22C {
    fn rule_id(&self) -> &'static str {
        "DCL22-C"
    }

    fn description(&self) -> &'static str {
        "Use volatile for data that cannot be cached"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL22-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        for n in query::find_descendants(*node, |_| true) {
            // Check function definitions for variables modified around function calls
            if n.kind() == "function_definition" {
                violations.extend(self.check_function_for_volatile_candidates(&n, source));
            }

            // Check declarations for sig_atomic_t without volatile
            if n.kind() == "declaration" {
                if let Some(violation) = self.check_sig_atomic_declaration(&n, source) {
                    violations.push(violation);
                }
            }
        }

        violations
    }
}

impl Dcl22C {
    /// Check function for variables that should be volatile
    /// Detects variables modified around function calls (pattern: write, call, write)
    fn check_function_for_volatile_candidates<'a>(
        &self,
        func_node: &Node<'a>,
        source: &str,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Get function body
        let body = match func_node.child_by_field_name("body") {
            Some(b) => b,
            None => return violations,
        };

        // Collect local declarations without volatile
        let mut non_volatile_vars: HashMap<String, Node<'a>> = HashMap::new();
        self.collect_non_volatile_declarations(&body, source, &mut non_volatile_vars);

        // Analyze statement sequences for pattern: assignment -> function call -> assignment
        let statements = self.get_statements(&body);
        for i in 0..statements.len().saturating_sub(2) {
            // Look for pattern across 3+ consecutive statements
            let var_before = self.get_assigned_variable(&statements[i], source);
            let has_call = self.contains_function_call(&statements[i + 1]);
            let var_after = self.get_assigned_variable(&statements[i + 2], source);

            if let (Some(var1), true, Some(var2)) = (var_before, has_call, var_after) {
                if var1 == var2 && non_volatile_vars.contains_key(&var1) {
                    // Found pattern: variable modified before and after function call
                    let decl_node = &non_volatile_vars[&var1];
                    let start_point = decl_node.start_position();

                    violations.push(RuleViolation {
                        rule_id: "DCL22-C".to_string(),
                        severity: Severity::Low,
                        message: format!(
                            "Variable '{}' should be declared volatile - modified around function calls that may have external side effects",
                            var1
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Declare as 'volatile' to prevent compiler optimizations that assume variable state is unchanged across function calls".to_string()
                        ),
                        requires_manual_review: None,
                    });

                    // Remove to avoid duplicate violations for same variable
                    non_volatile_vars.remove(&var1);
                }
            }
        }

        violations
    }

    /// Collect all local variable declarations that are not volatile
    fn collect_non_volatile_declarations<'a>(
        &self,
        body: &Node<'a>,
        source: &str,
        vars: &mut HashMap<String, Node<'a>>,
    ) {
        let mut cursor = body.walk();
        for child in body.children(&mut cursor) {
            if child.kind() == "declaration" {
                let type_text = self.get_type_text(&child, source).unwrap_or_default();
                if !type_text.contains("volatile") {
                    if let Some(var_name) = self.get_variable_name(&child, source) {
                        vars.insert(var_name, child);
                    }
                }
            } else if child.kind() == "compound_statement" {
                self.collect_non_volatile_declarations(&child, source, vars);
            }
        }
    }

    /// Get all statements from a compound statement
    fn get_statements<'a>(&self, body: &'a Node) -> Vec<Node<'a>> {
        let mut statements = Vec::new();
        let mut cursor = body.walk();
        for child in body.children(&mut cursor) {
            if !matches!(child.kind(), "{" | "}") {
                statements.push(child);
            }
        }
        statements
    }

    /// Get variable name from an assignment statement
    fn get_assigned_variable(&self, stmt: &Node, source: &str) -> Option<String> {
        // Look for expression_statement containing assignment_expression
        if stmt.kind() == "expression_statement" {
            let mut cursor = stmt.walk();
            for child in stmt.children(&mut cursor) {
                if child.kind() == "assignment_expression" {
                    // Get left side of assignment
                    if let Some(left) = child.child_by_field_name("left") {
                        return self.extract_base_identifier(&left, source);
                    }
                }
            }
        }
        None
    }

    /// Extract base identifier from expression (handles array subscripts)
    fn extract_base_identifier(&self, node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => Some(ast_utils::get_node_text(node, source).to_string()),
            "subscript_expression" => {
                // For bank[0], extract "bank"
                if let Some(array) = node.child_by_field_name("argument") {
                    return self.extract_base_identifier(&array, source);
                }
                None
            }
            _ => None,
        }
    }

    /// Check if a statement contains a function call
    fn contains_function_call(&self, stmt: &Node) -> bool {
        if stmt.kind() == "expression_statement" {
            let mut cursor = stmt.walk();
            for child in stmt.children(&mut cursor) {
                if child.kind() == "call_expression" {
                    return true;
                }
            }
        }
        false
    }

    /// Check if a sig_atomic_t declaration is missing volatile qualifier
    fn check_sig_atomic_declaration(
        &self,
        decl_node: &Node,
        source: &str,
    ) -> Option<RuleViolation> {
        // Get the type specifier
        let type_text = self.get_type_text(decl_node, source)?;

        // Check if it's sig_atomic_t
        if type_text.contains("sig_atomic_t") {
            // Check if volatile is present
            if !type_text.contains("volatile") {
                let start_point = decl_node.start_position();
                let var_name = self
                    .get_variable_name(decl_node, source)
                    .unwrap_or_else(|| "<unknown>".to_string());

                return Some(RuleViolation {
                    rule_id: "DCL22-C".to_string(),
                    severity: Severity::Low,
                    message: format!(
                        "Variable '{}' of type 'sig_atomic_t' should be declared volatile for signal handler safety",
                        var_name
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Declare as 'volatile sig_atomic_t' to prevent compiler optimizations that could cause race conditions".to_string()
                    ),
                    requires_manual_review: None,
                });
            }
        }

        None
    }

    /// Get the full type text from a declaration
    fn get_type_text(&self, decl_node: &Node, source: &str) -> Option<String> {
        let mut type_parts = Vec::new();

        let mut cursor = decl_node.walk();
        for child in decl_node.children(&mut cursor) {
            match child.kind() {
                "type_qualifier"
                | "storage_class_specifier"
                | "primitive_type"
                | "type_identifier"
                | "struct_specifier" => {
                    let text = ast_utils::get_node_text(&child, source);
                    type_parts.push(text.to_string());
                }
                _ => {}
            }
        }

        if type_parts.is_empty() {
            None
        } else {
            Some(type_parts.join(" "))
        }
    }

    /// Get the variable name from a declaration
    fn get_variable_name(&self, decl_node: &Node, source: &str) -> Option<String> {
        let mut cursor = decl_node.walk();
        for child in decl_node.children(&mut cursor) {
            if child.kind() == "init_declarator" {
                if let Some(declarator) = child.child_by_field_name("declarator") {
                    return self.extract_identifier(&declarator, source);
                }
            } else if matches!(
                child.kind(),
                "identifier" | "pointer_declarator" | "array_declarator"
            ) {
                return self.extract_identifier(&child, source);
            }
        }
        None
    }

    /// Extract identifier from declarator
    fn extract_identifier(&self, node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => Some(ast_utils::get_node_text(node, source).to_string()),
            "pointer_declarator" | "array_declarator" => {
                if let Some(child_declarator) = node.child_by_field_name("declarator") {
                    return self.extract_identifier(&child_declarator, source);
                }
                // Fallback: search for identifier child
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "identifier" {
                        return Some(ast_utils::get_node_text(&child, source).to_string());
                    }
                }
                None
            }
            _ => None,
        }
    }
}
