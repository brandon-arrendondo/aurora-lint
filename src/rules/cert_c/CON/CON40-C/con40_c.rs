// CON40-C: Do not refer to an atomic variable twice in an expression
//
// This rule detects when an atomic variable is referenced multiple times
// in a single expression, which creates a race condition between the
// atomic reads/writes.
//
// Detection strategy:
// 1. Find all atomic variable declarations (atomic_int, atomic_bool, etc.)
// 2. Check expressions for multiple references to the same atomic variable
// 3. Flag violations when:
//    - Same atomic var appears 2+ times in binary/assignment expressions
//    - Excluding compound assignments (+=, ^=, etc.) which are thread-safe

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Con40C;

impl Con40C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Con40C
    }

    /// Check a node and all its descendants for violations
    fn check_node<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Track atomic variables in scope
        let mut atomic_vars = HashMap::new();
        self.collect_atomic_vars(node, source, &mut atomic_vars);

        // Check expressions for multiple references to same atomic var
        self.check_expressions(node, source, &atomic_vars, violations);

        // Check for load-modify-store patterns
        self.check_load_modify_store(node, source, &atomic_vars, violations);
    }

    /// Collect all atomic variable declarations
    fn collect_atomic_vars<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        atomic_vars: &mut HashMap<String, bool>,
    ) {
        // Check if this is an atomic variable declaration
        for decl in query::find_descendants_of_kind(*node, "declaration") {
            if let Some(type_node) = decl.child_by_field_name("type") {
                let type_text = get_node_text(&type_node, source);

                // Check for atomic types
                if type_text.contains("atomic_") || type_text.contains("_Atomic") {
                    // Find the declarator(s)
                    for i in 0..decl.child_count() {
                        if let Some(child) = decl.child(i) {
                            if child.kind() == "init_declarator" || child.kind() == "identifier" {
                                if let Some(id) = self.get_identifier(&child, source) {
                                    atomic_vars.insert(id.to_string(), true);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Get identifier name from a declarator node
    #[allow(clippy::only_used_in_recursion)]
    fn get_identifier<'a>(&self, node: &Node<'a>, source: &'a str) -> Option<&'a str> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source));
        }

        if node.kind() == "init_declarator" {
            if let Some(declarator) = node.child_by_field_name("declarator") {
                return self.get_identifier(&declarator, source);
            }
        }

        // Recurse to find identifier
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source));
                }
                if let Some(id) = self.get_identifier(&child, source) {
                    return Some(id);
                }
            }
        }

        None
    }

    /// Check all expressions for multiple references to atomic variables
    fn check_expressions<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        atomic_vars: &HashMap<String, bool>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let expr_kinds = [
            "binary_expression",
            "assignment_expression",
            "call_expression",
            "conditional_expression",
            "unary_expression",
            "parenthesized_expression",
        ];

        for expr in query::find_descendants_of_kinds(*node, &expr_kinds) {
            // Count references to each atomic variable in this expression
            let mut var_counts: HashMap<String, Vec<Node>> = HashMap::new();
            self.count_var_references(&expr, source, atomic_vars, &mut var_counts);

            // Check for variables referenced multiple times
            for (var_name, refs) in &var_counts {
                if refs.len() >= 2 {
                    // Check if this is a compound assignment (which is safe)
                    if !self.is_safe_compound_assignment(&expr, source, var_name) {
                        // Report violation on the expression node
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            line: expr.start_position().row + 1,
                            column: expr.start_position().column + 1,
                            message: format!(
                                "Atomic variable '{}' referenced {} times in single expression - creates race condition",
                                var_name, refs.len()
                            ),
                            severity: self.severity(),
                            file_path: String::new(),
                            suggestion: None,
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }
    }

    /// Count references to atomic variables within an expression
    #[allow(clippy::only_used_in_recursion)]
    fn count_var_references<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        atomic_vars: &HashMap<String, bool>,
        var_counts: &mut HashMap<String, Vec<Node<'a>>>,
    ) {
        // If this is an identifier, check if it's an atomic var
        if node.kind() == "identifier" {
            let var_name = get_node_text(node, source);
            if atomic_vars.contains_key(var_name) {
                var_counts
                    .entry(var_name.to_string())
                    .or_default()
                    .push(*node);
            }
        }

        // Don't recurse into function calls - they're separate atomic operations
        if node.kind() == "call_expression" {
            return;
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.count_var_references(&child, source, atomic_vars, var_counts);
            }
        }
    }

    /// Check if this is a safe compound assignment operation
    fn is_safe_compound_assignment(&self, node: &Node, source: &str, var_name: &str) -> bool {
        // Compound assignments like +=, -=, *=, /=, ^=, etc. are atomic operations
        let is_compound_assignment_on_var = |n: &Node| -> bool {
            if n.kind() != "assignment_expression" {
                return false;
            }
            let Some(op) = n.child_by_field_name("operator") else {
                return false;
            };
            // Check for compound assignment operators
            if get_node_text(&op, source) == "=" {
                return false;
            }
            // This is a compound assignment - check if it's operating on our var
            n.child_by_field_name("left")
                .map(|left| get_node_text(&left, source) == var_name)
                .unwrap_or(false)
        };

        // Check this node, then walk up parent nodes for compound assignment context
        is_compound_assignment_on_var(node)
            || query::find_ancestor(*node, |n| is_compound_assignment_on_var(&n)).is_some()
    }

    /// Check for load-modify-store patterns using atomic_load/atomic_store
    fn check_load_modify_store<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        atomic_vars: &HashMap<String, bool>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check every function definition (including nested ones)
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            // Get the function body
            let Some(body) = func.child_by_field_name("body") else {
                continue;
            };

            // Look for atomic_load calls followed by atomic_store on the same variable
            let mut loads: HashMap<String, Node> = HashMap::new();
            let mut stores: HashMap<String, Node> = HashMap::new();

            self.collect_atomic_operations(&body, source, atomic_vars, &mut loads, &mut stores);

            // Check if any variable has both load and store in the same function
            for (var_name, load_node) in &loads {
                if stores.contains_key(var_name) {
                    // This is a potential load-modify-store pattern
                    // Report violation at the load site
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        line: load_node.start_position().row + 1,
                        column: load_node.start_position().column + 1,
                        message: format!(
                            "Non-atomic load-modify-store pattern detected on atomic variable '{}' - use atomic operations or mutex protection",
                            var_name
                        ),
                        severity: self.severity(),
                        file_path: String::new(),
                        suggestion: Some("Consider using atomic_fetch_* operations or wrap with mutex locks".to_string()),
                        requires_manual_review: None,
                    });
                }
            }
        }
    }

    /// Collect atomic_load and atomic_store operations
    fn collect_atomic_operations<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        atomic_vars: &HashMap<String, bool>,
        loads: &mut HashMap<String, Node<'a>>,
        stores: &mut HashMap<String, Node<'a>>,
    ) {
        // Look for call expressions
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = call.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);

                // Check for atomic_load
                if func_name == "atomic_load" {
                    // Get the argument - should be &flag or similar
                    if let Some(args) = call.child_by_field_name("arguments") {
                        if let Some(var_name) =
                            self.extract_atomic_var_from_args(&args, source, atomic_vars)
                        {
                            loads.insert(var_name.to_string(), call);
                        }
                    }
                }

                // Check for atomic_store
                if func_name == "atomic_store" {
                    if let Some(args) = call.child_by_field_name("arguments") {
                        if let Some(var_name) =
                            self.extract_atomic_var_from_args(&args, source, atomic_vars)
                        {
                            stores.insert(var_name.to_string(), call);
                        }
                    }
                }
            }
        }
    }

    /// Extract atomic variable name from function arguments like &flag
    fn extract_atomic_var_from_args<'a>(
        &self,
        args_node: &Node<'a>,
        source: &'a str,
        atomic_vars: &HashMap<String, bool>,
    ) -> Option<&'a str> {
        // Iterate through arguments
        for i in 0..args_node.child_count() {
            if let Some(arg) = args_node.child(i) {
                // Look for address-of expressions: &flag
                if arg.kind() == "pointer_expression" {
                    if let Some(operand) = arg.child_by_field_name("argument") {
                        let var_name = get_node_text(&operand, source);
                        if atomic_vars.contains_key(var_name) {
                            return Some(var_name);
                        }
                    }
                }
                // Also check for direct identifiers
                if arg.kind() == "identifier" {
                    let var_name = get_node_text(&arg, source);
                    if atomic_vars.contains_key(var_name) {
                        return Some(var_name);
                    }
                }
            }
        }
        None
    }
}

impl CertRule for Con40C {
    fn rule_id(&self) -> &'static str {
        "CON40-C"
    }

    fn description(&self) -> &'static str {
        "Do not refer to an atomic variable twice in an expression"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "CON40-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}
