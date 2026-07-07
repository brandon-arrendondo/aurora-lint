// DCL07-C: Include the appropriate type information in function declarators
//
// This rule detects function declarators that lack proper type information:
// 1. Old K&R style function definitions (identifier-list form)
// 2. Function pointer declarations that don't match actual function signatures
//
// Detection strategy:
// 1. Find K&R style function definitions (parameters declared after closing paren)
// 2. Find function pointer assignments where signature doesn't match
//
// Note: implicit function declaration (calling before declaring) is handled by
// DCL31-C to avoid duplicate violations.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use std::cell::RefCell;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Dcl07C {
    // Functions known from pre-scanned directories (cross-file context)
    cross_file_functions: RefCell<HashSet<String>>,
}

impl Dcl07C {
    pub fn new() -> Self {
        Dcl07C {
            cross_file_functions: RefCell::new(HashSet::new()),
        }
    }

    /// Check a node and all its descendants for violations
    fn check_node<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for K&R style function definitions
        if node.kind() == "function_definition" {
            self.check_kr_style_function(node, source, violations);
        }

        // Check for function pointer mismatches
        if node.kind() == "assignment_expression" {
            self.check_function_pointer_assignment(node, source, violations);
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_node(&child, source, violations);
            }
        }
    }

    /// Check for K&R style function definitions (old identifier-list form)
    fn check_kr_style_function<'a>(
        &self,
        func_node: &Node<'a>,
        _source: &'a str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // K&R style has form:
        // int max(a, b)
        // int a, b;
        // { ... }
        //
        // The key is that there are declarations between the declarator and the body

        if let Some(declarator) = func_node.child_by_field_name("declarator") {
            // Check if there are parameter declarations after the declarator
            let mut found_declarations_after_declarator = false;
            let declarator_end = declarator.end_byte();

            // Look for declarations between declarator and body
            for i in 0..func_node.child_count() {
                if let Some(child) = func_node.child(i) {
                    if child.start_byte() > declarator_end && child.kind() == "declaration" {
                        // Check if this is before the body
                        if let Some(body) = func_node.child_by_field_name("body") {
                            if child.start_byte() < body.start_byte() {
                                found_declarations_after_declarator = true;
                                break;
                            }
                        }
                    }
                }
            }

            if found_declarations_after_declarator {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    line: func_node.start_position().row + 1,
                    column: func_node.start_position().column + 1,
                    message: "Function uses K&R style (identifier-list) parameter declarations - use prototype form with type information in parameter list".to_string(),
                    severity: self.severity(),
                    file_path: String::new(),
                    suggestion: Some("Declare parameters with types in the parameter list: int max(int a, int b)".to_string()),
                    requires_manual_review: None,
                });
            }
        }
    }

    /// Check for function pointer assignments with mismatched signatures
    fn check_function_pointer_assignment<'a>(
        &self,
        assign_node: &Node<'a>,
        source: &'a str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for: fn_ptr = add;
        // Where fn_ptr is declared as: int (*fn_ptr)(int, int);
        // But add is: int add(int, int, int);

        if let Some(right) = assign_node.child_by_field_name("right") {
            // Check if right side is an identifier (function name)
            if right.kind() == "identifier" {
                let func_name = get_node_text(&right, source);

                // Get the left side (function pointer variable)
                if let Some(left) = assign_node.child_by_field_name("left") {
                    // Find the function pointer declaration
                    if let Some(ptr_params) =
                        self.find_function_pointer_params(&left, source, assign_node)
                    {
                        // Find the actual function definition
                        if let Some(func_params) =
                            self.find_function_definition_params(func_name, source, assign_node)
                        {
                            // Compare parameter counts
                            if ptr_params != func_params {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    line: assign_node.start_position().row + 1,
                                    column: assign_node.start_position().column + 1,
                                    message: format!(
                                        "Function pointer assignment has mismatched signature: pointer expects {} parameters but function '{}' has {} parameters",
                                        ptr_params, func_name, func_params
                                    ),
                                    severity: self.severity(),
                                    file_path: String::new(),
                                    suggestion: Some(format!(
                                        "Declare function pointer with correct number of parameters to match '{}'",
                                        func_name
                                    )),
                                    requires_manual_review: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Find parameter count from function pointer declaration
    fn find_function_pointer_params<'a>(
        &self,
        var_node: &Node<'a>,
        source: &'a str,
        context: &Node<'a>,
    ) -> Option<usize> {
        // Get variable name
        let var_name = if var_node.kind() == "identifier" {
            get_node_text(var_node, source)
        } else {
            return None;
        };

        // Search backwards for declaration
        let root = self.get_root(context);
        self.find_declaration_params(&root, source, var_name)
    }

    /// Get root node
    fn get_root<'a>(&self, node: &Node<'a>) -> Node<'a> {
        let mut current = *node;
        while let Some(parent) = current.parent() {
            current = parent;
        }
        current
    }

    /// Find declaration and count parameters
    fn find_declaration_params<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        var_name: &str,
    ) -> Option<usize> {
        if node.kind() == "declaration" {
            // Check if this declares our variable
            let decl_text = get_node_text(node, source);
            if decl_text.contains(var_name) && decl_text.contains("(*") {
                // This is a function pointer declaration
                // Count parameters in the parameter list
                return self.count_params_in_declaration(node, source);
            }
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(count) = self.find_declaration_params(&child, source, var_name) {
                    return Some(count);
                }
            }
        }

        None
    }

    /// Count parameters in a function pointer declaration
    fn count_params_in_declaration<'a>(
        &self,
        decl_node: &Node<'a>,
        source: &'a str,
    ) -> Option<usize> {
        // Look for parameter_list in the declaration
        for i in 0..decl_node.child_count() {
            if let Some(child) = decl_node.child(i) {
                if let Some(count) = self.find_and_count_params(&child, source) {
                    return Some(count);
                }
            }
        }
        None
    }

    /// Find parameter_list and count parameters
    fn find_and_count_params<'a>(&self, node: &Node<'a>, source: &'a str) -> Option<usize> {
        if node.kind() == "parameter_list" || node.kind() == "parameter_declaration" {
            return Some(self.count_parameters(node, source));
        }

        // Recurse
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(count) = self.find_and_count_params(&child, source) {
                    return Some(count);
                }
            }
        }

        None
    }

    /// Count parameters in a parameter_list node
    fn count_parameters<'a>(&self, params_node: &Node<'a>, source: &'a str) -> usize {
        let mut count = 0;

        for i in 0..params_node.child_count() {
            if let Some(child) = params_node.child(i) {
                if child.kind() == "parameter_declaration" {
                    count += 1;
                } else if child.kind() == "parameter_list" {
                    count = self.count_parameters(&child, source);
                }
            }
        }

        // If we didn't find any parameter_declaration nodes, count commas + 1
        if count == 0 {
            let text = get_node_text(params_node, source);
            // Don't count if it's void or empty
            if text.trim() != "()" && text.trim() != "(void)" && !text.trim().is_empty() {
                count = text.matches(',').count() + 1;
            }
        }

        count
    }

    /// Find function definition and count parameters
    fn find_function_definition_params<'a>(
        &self,
        func_name: &str,
        source: &'a str,
        context: &Node<'a>,
    ) -> Option<usize> {
        let root = self.get_root(context);
        self.search_function_definition(&root, source, func_name)
    }

    /// Search for function definition by name
    fn search_function_definition<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        func_name: &str,
    ) -> Option<usize> {
        if node.kind() == "function_definition" {
            if let Some(declarator) = node.child_by_field_name("declarator") {
                if let Some(name) = self.get_function_name(&declarator, source) {
                    if name == func_name {
                        // Found it! Count parameters
                        return self.count_function_params(&declarator, source);
                    }
                }
            }
        }

        // Recurse
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(count) = self.search_function_definition(&child, source, func_name) {
                    return Some(count);
                }
            }
        }

        None
    }

    /// Get function name from declarator
    fn get_function_name<'a>(&self, declarator: &Node<'a>, source: &'a str) -> Option<&'a str> {
        match declarator.kind() {
            "identifier" => Some(get_node_text(declarator, source)),
            "function_declarator" => {
                if let Some(inner) = declarator.child_by_field_name("declarator") {
                    self.get_function_name(&inner, source)
                } else {
                    None
                }
            }
            "pointer_declarator" => {
                if let Some(inner) = declarator.child_by_field_name("declarator") {
                    self.get_function_name(&inner, source)
                } else {
                    None
                }
            }
            _ => {
                // Search children
                for i in 0..declarator.child_count() {
                    if let Some(child) = declarator.child(i) {
                        if child.kind() == "identifier" {
                            return Some(get_node_text(&child, source));
                        }
                        if let Some(name) = self.get_function_name(&child, source) {
                            return Some(name);
                        }
                    }
                }
                None
            }
        }
    }

    /// Count function parameters from declarator
    fn count_function_params<'a>(&self, declarator: &Node<'a>, source: &'a str) -> Option<usize> {
        if declarator.kind() == "function_declarator" {
            if let Some(params) = declarator.child_by_field_name("parameters") {
                return Some(self.count_parameters(&params, source));
            }
        }

        // Recurse to find function_declarator
        for i in 0..declarator.child_count() {
            if let Some(child) = declarator.child(i) {
                if let Some(count) = self.count_function_params(&child, source) {
                    return Some(count);
                }
            }
        }

        None
    }
}

impl CertRule for Dcl07C {
    fn rule_id(&self) -> &'static str {
        "DCL07-C"
    }

    fn description(&self) -> &'static str {
        "Include the appropriate type information in function declarators"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL07-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        let mut funcs = context.known_functions.clone();
        funcs.extend(context.header_declared_functions.clone());
        for alias_name in context.macro_aliases.keys() {
            funcs.insert(alias_name.clone());
        }
        *self.cross_file_functions.borrow_mut() = funcs;
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}
