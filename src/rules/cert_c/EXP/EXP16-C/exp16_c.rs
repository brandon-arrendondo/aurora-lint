//! EXP16-C: Do not compare function pointers to constant values
//!
//! This rule detects comparisons of function pointers to constant values
//! (other than null pointers). This typically indicates programmer error
//! where the function was intended to be called but the parentheses were omitted.
//!
//! VIOLATIONS:
//! - if (getuid == 0)      // Function identifier compared to constant
//! - if (geteuid != 0)     // Function identifier compared to constant
//! - if (do_xyz)           // Function identifier used as boolean (implicit != 0)
//!
//! COMPLIANT:
//! - if (getuid() == 0)    // Function is called, result compared
//! - if (geteuid() != 0)   // Function is called, result compared
//! - if (do_xyz())         // Function is called, result used as boolean

use std::collections::HashSet;

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Exp16C;

impl CertRule for Exp16C {
    fn rule_id(&self) -> &'static str {
        "EXP16-C"
    }

    fn description(&self) -> &'static str {
        "Do not compare function pointers to constant values"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "EXP16-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let function_names = self.collect_function_names(node, source);
        self.check_node(node, source, &function_names, &mut violations);
        violations
    }
}

impl Exp16C {
    /// Collect all function names defined or declared in this translation unit.
    fn collect_function_names(&self, node: &Node, source: &str) -> HashSet<String> {
        let mut names = HashSet::new();
        self.collect_function_names_recursive(node, source, &mut names);
        names
    }

    fn collect_function_names_recursive(
        &self,
        node: &Node,
        source: &str,
        names: &mut HashSet<String>,
    ) {
        for n in query::find_descendants_of_kinds(*node, &["function_definition", "declaration"]) {
            match n.kind() {
                "function_definition" => {
                    if let Some(name) = self.extract_function_name(&n, source) {
                        names.insert(name);
                    }
                }
                "declaration" => {
                    // Forward declarations: check if declarator contains a function_declarator
                    if let Some(declarator) = n.child_by_field_name("declarator") {
                        if self.has_function_declarator(&declarator) {
                            if let Some(name) = self.extract_declarator_name(&declarator, source) {
                                names.insert(name);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn extract_function_name(&self, func_def: &Node, source: &str) -> Option<String> {
        let declarator = func_def.child_by_field_name("declarator")?;
        self.extract_declarator_name(&declarator, source)
    }

    fn extract_declarator_name(&self, node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => Some(node.utf8_text(source.as_bytes()).ok()?.to_string()),
            "function_declarator" | "pointer_declarator" | "parenthesized_declarator" => {
                let child = node.child_by_field_name("declarator")?;
                self.extract_declarator_name(&child, source)
            }
            _ => {
                // Walk children looking for an identifier
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if let Some(name) = self.extract_declarator_name(&child, source) {
                            return Some(name);
                        }
                    }
                }
                None
            }
        }
    }

    fn has_function_declarator(&self, node: &Node) -> bool {
        query::find_first_descendant(*node, |n| n.kind() == "function_declarator").is_some()
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        function_names: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let kinds = [
            "binary_expression",
            "expression_statement",
            "if_statement",
            "while_statement",
            "parenthesized_expression",
        ];
        for n in query::find_descendants_of_kinds(*node, &kinds) {
            match n.kind() {
                // Check binary expressions for comparisons
                "binary_expression" => {
                    self.check_binary_expression(&n, source, function_names, violations);
                }
                // Check for standalone comparison as expression statement (CWE-482)
                // e.g., `x == 5;` where the result is discarded
                "expression_statement" => {
                    self.check_dead_comparison(&n, source, violations);
                }
                // Check if/while conditions for implicit boolean conversion
                "if_statement" | "while_statement" => {
                    if let Some(condition) = n.child_by_field_name("condition") {
                        self.check_condition_for_implicit_conversion(
                            &condition,
                            source,
                            function_names,
                            violations,
                        );
                    }
                }
                // Check parenthesized expressions in conditions
                "parenthesized_expression" => {
                    // Check if this is directly inside an if/while (the condition)
                    if let Some(parent) = n.parent() {
                        if parent.kind() == "if_statement" || parent.kind() == "while_statement" {
                            // Check the inner expression
                            for i in 0..n.child_count() {
                                if let Some(child) = n.child(i) {
                                    if child.kind() == "identifier" {
                                        self.check_identifier_as_condition(
                                            &child,
                                            source,
                                            function_names,
                                            violations,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn check_binary_expression(
        &self,
        node: &Node,
        source: &str,
        function_names: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the operator
        let mut operator = None;
        let mut left = None;
        let mut right = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "==" | "!=" | "<" | ">" | "<=" | ">=" => {
                        operator = Some(child.kind());
                    }
                    _ => {
                        if left.is_none() {
                            left = Some(child);
                        } else if right.is_none() {
                            right = Some(child);
                        }
                    }
                }
            }
        }

        // Only check comparison operators
        if let (Some(op), Some(left_node), Some(right_node)) = (operator, left, right) {
            if op == "==" || op == "!=" || op == "<" || op == ">" || op == "<=" || op == ">=" {
                // Check if left side is a function identifier and right is a constant
                if self.is_function_identifier(&left_node, source, function_names)
                    && self.is_constant(&right_node, source)
                {
                    let func_name = left_node.utf8_text(source.as_bytes()).unwrap_or("unknown");
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        file_path: String::new(),
                        message: format!(
                            "Function pointer '{}' compared to constant value; did you mean to call the function?",
                            func_name
                        ),
                        suggestion: Some(format!(
                            "Use '{}()' to call the function instead of comparing its address",
                            func_name
                        )),
                        requires_manual_review: None,
                    });
                }

                // Check if right side is a function identifier and left is a constant
                if self.is_function_identifier(&right_node, source, function_names)
                    && self.is_constant(&left_node, source)
                {
                    let func_name = right_node.utf8_text(source.as_bytes()).unwrap_or("unknown");
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        file_path: String::new(),
                        message: format!(
                            "Function pointer '{}' compared to constant value; did you mean to call the function?",
                            func_name
                        ),
                        suggestion: Some(format!(
                            "Use '{}()' to call the function instead of comparing its address",
                            func_name
                        )),
                        requires_manual_review: None,
                    });
                }
            }
        }
    }

    /// Detect `x == value;` as a standalone expression statement (CWE-482).
    /// The comparison result is discarded — likely meant `x = value;`.
    fn check_dead_comparison(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // expression_statement wraps one child expression + ";"
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "binary_expression" {
                    // Check if operator is == or !=
                    for j in 0..child.child_count() {
                        if let Some(op) = child.child(j) {
                            if op.kind() == "==" {
                                let expr_text =
                                    child.utf8_text(source.as_bytes()).unwrap_or("unknown");
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: self.severity(),
                                    line: child.start_position().row + 1,
                                    column: child.start_position().column + 1,
                                    file_path: String::new(),
                                    message: format!(
                                        "Comparison '{}' used as statement with result discarded; did you mean '=' (assignment)?",
                                        expr_text
                                    ),
                                    suggestion: Some(
                                        "Use '=' for assignment instead of '==' for comparison"
                                            .to_string(),
                                    ),
                                    requires_manual_review: None,
                                });
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    fn check_condition_for_implicit_conversion(
        &self,
        node: &Node,
        source: &str,
        function_names: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for parenthesized expression containing just an identifier
        if node.kind() == "parenthesized_expression" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" {
                        self.check_identifier_as_condition(
                            &child,
                            source,
                            function_names,
                            violations,
                        );
                    }
                }
            }
        }
    }

    fn check_identifier_as_condition(
        &self,
        node: &Node,
        source: &str,
        function_names: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // An identifier used directly in a condition is implicitly compared to 0
        if self.is_function_identifier(node, source, function_names) {
            let func_name = node.utf8_text(source.as_bytes()).unwrap_or("unknown");
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                file_path: String::new(),
                message: format!(
                    "Function pointer '{}' used in boolean context; did you mean to call the function?",
                    func_name
                ),
                suggestion: Some(format!(
                    "Use '{}()' to call the function instead of testing its address",
                    func_name
                )),
                requires_manual_review: None,
            });
        }
    }

    fn is_function_identifier(
        &self,
        node: &Node,
        source: &str,
        function_names: &HashSet<String>,
    ) -> bool {
        if node.kind() != "identifier" {
            return false;
        }

        let name = node.utf8_text(source.as_bytes()).unwrap_or("");

        // If this identifier is being called (parent is call_expression), it's fine
        if let Some(parent) = node.parent() {
            if parent.kind() == "call_expression" {
                if let Some(func) = parent.child_by_field_name("function") {
                    if func.id() == node.id() {
                        return false;
                    }
                }
            }
        }

        // Check against function names collected from the AST
        if function_names.contains(name) {
            return true;
        }

        // Fallback: well-known standard library functions
        const KNOWN_FUNCTIONS: &[&str] = &[
            "getuid", "geteuid", "getgid", "getegid", "getpid", "getppid", "fork", "exit", "main",
            "printf", "scanf", "malloc", "free", "strlen", "strcpy", "strcat", "strcmp", "memcpy",
            "memset", "fopen", "fclose", "fread", "fwrite", "rand", "srand",
        ];
        KNOWN_FUNCTIONS.contains(&name)
    }

    fn is_constant(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            "number_literal" | "char_literal" | "true" | "false" | "null" => true,
            "identifier" => {
                let text = node.utf8_text(source.as_bytes()).unwrap_or("");
                text == "NULL" || text == "nullptr"
            }
            _ => false,
        }
    }
}
