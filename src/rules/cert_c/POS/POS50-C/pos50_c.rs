// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Ryan Urchick

//! POS50-C: Declare objects shared between POSIX threads with appropriate storage durations
//!
//! This rule detects passing the address of automatic (local) or thread-local storage variables
//! to pthread_create(), which can lead to undefined behavior when the thread outlives the
//! variable's lifetime.
//!
//! Violations:
//! - Passing address of local variable (&var) to pthread_create() as argument
//! - Passing address of thread-local variable (__thread) to pthread_create()
//!
//! Compliant:
//! - Pass address of static/global variables
//! - Pass dynamically allocated memory
//! - Pass pointers with appropriate lifetimes

use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;

/// POS50-C: Declare objects shared between POSIX threads with appropriate storage durations
pub struct Pos50C;

impl CertRule for Pos50C {
    fn rule_id(&self) -> &'static str {
        "POS50-C"
    }

    fn description(&self) -> &'static str {
        "Declare objects shared between POSIX threads with appropriate storage durations"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "POS50-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        self.check_toctou(node, source, &mut violations);
        violations
    }
}

impl Pos50C {
    /// Recursively check nodes for POS50-C violations
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for pthread_create calls
        if node.kind() == "call_expression" {
            if let Some(func_node) = node.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);
                if func_name.trim() == "pthread_create" {
                    self.check_pthread_create(node, source, violations);
                }
            }
        }

        // Recursively check children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.check_node(&child, source, violations);
        }
    }

    /// Check pthread_create call for improper storage duration
    fn check_pthread_create(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // pthread_create(pthread_t *thread, const pthread_attr_t *attr,
        //               void *(*start_routine)(void *), void *arg)
        // The 4th argument (arg) is what we're interested in

        if let Some(args) = node.child_by_field_name("arguments") {
            if let Some(arg_node) = self.get_fourth_argument(&args) {
                // Check if it's an address-of operator on a local/thread-local variable
                if self.is_address_of_local_or_thread_local(&arg_node, node, source) {
                    let position = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: position.row + 1,
                        column: position.column + 1,
                        file_path: String::new(),
                        message:
                            "Passing address of automatic or thread-local storage to pthread_create(). \
                            The thread may outlive the variable's lifetime, causing undefined behavior."
                                .to_string(),
                        suggestion: Some(
                            "Use static storage duration (global/static variables) or dynamically \
                            allocated memory for data shared between threads.".to_string()
                        ),
                        requires_manual_review: None,
                    });
                }
            }
        }
    }

    /// Get the fourth argument from pthread_create argument list
    fn get_fourth_argument<'a>(&self, args_node: &'a Node) -> Option<Node<'a>> {
        let mut arg_count = 0;
        let mut cursor = args_node.walk();
        for child in args_node.children(&mut cursor) {
            if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                arg_count += 1;
                if arg_count == 4 {
                    return Some(child);
                }
            }
        }
        None
    }

    /// Check if an expression is the address of a local or thread-local variable
    fn is_address_of_local_or_thread_local(
        &self,
        node: &Node,
        pthread_node: &Node,
        source: &str,
    ) -> bool {
        // Check if the node itself is a unary & expression
        if node.kind() == "unary_expression" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = get_node_text(&op, source);
                if op_text.trim() == "&" {
                    // Get the operand
                    if let Some(operand) = node.child_by_field_name("argument") {
                        if let Some(var_name) = self.extract_identifier(&operand, source) {
                            // Check if this variable is local or thread-local
                            return self.is_local_or_thread_local(&var_name, pthread_node, source);
                        }
                    }
                }
            }
        }

        // Also check if node contains a pointer expression that references local variable
        // This handles cases where the AST structure is different
        let node_text = get_node_text(node, source);
        if node_text.trim().starts_with('&') {
            // Extract variable name after &
            let var_part = node_text.trim().trim_start_matches('&');
            let var_name = var_part
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .next()
                .unwrap_or("")
                .to_string();
            if !var_name.is_empty() {
                return self.is_local_or_thread_local(&var_name, pthread_node, source);
            }
        }

        false
    }

    /// Extract identifier from a node
    fn extract_identifier(&self, node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => Some(get_node_text(node, source).trim().to_string()),
            "cast_expression" => {
                if let Some(value) = node.child_by_field_name("value") {
                    return self.extract_identifier(&value, source);
                }
                None
            }
            _ => None,
        }
    }

    /// Check if a variable is locally declared or thread-local
    fn is_local_or_thread_local(&self, var_name: &str, node: &Node, source: &str) -> bool {
        // Find the declaration of this variable
        // Walk up to find the containing function
        let mut parent = node.parent();
        while let Some(p) = parent {
            if p.kind() == "function_definition" {
                // Check if variable is declared locally in this function
                if self.is_declared_in_function(&p, var_name, source) {
                    return true;
                }
            }
            parent = p.parent();
        }

        // File-scope thread-local variables are SAFE (they have static storage duration per-thread)
        // So we don't check for thread-local globals here

        false
    }

    /// Check if a variable is declared within a function (local variable)
    fn is_declared_in_function(&self, func_node: &Node, var_name: &str, source: &str) -> bool {
        // Look for declarations in the function body
        if let Some(body) = func_node.child_by_field_name("body") {
            return self.search_for_declaration(&body, var_name, source);
        }
        false
    }

    /// Search for a variable declaration
    fn search_for_declaration(&self, node: &Node, var_name: &str, source: &str) -> bool {
        if node.kind() == "declaration" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(name) = self.get_declarator_name(&child, source) {
                    if name == var_name {
                        return true;
                    }
                }
            }
        }

        // Recursively search children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if self.search_for_declaration(&child, var_name, source) {
                return true;
            }
        }

        false
    }

    /// Get the declared variable name from a declarator
    fn get_declarator_name(&self, node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "init_declarator" => {
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    return self.get_declarator_name(&declarator, source);
                }
                None
            }
            "identifier" => Some(get_node_text(node, source).trim().to_string()),
            "pointer_declarator" | "array_declarator" => {
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    return self.get_declarator_name(&declarator, source);
                }
                None
            }
            _ => None,
        }
    }

    /// Check if a variable is declared with __thread at file scope
    #[allow(dead_code)]
    fn is_thread_local_global(&self, root_node: &Node, var_name: &str, source: &str) -> bool {
        let mut cursor = root_node.walk();
        for child in root_node.children(&mut cursor) {
            if child.kind() == "declaration" {
                // Check for __thread storage class specifier
                let has_thread_local = self.has_thread_local_specifier(&child, source);

                // Check if this declaration declares our variable
                let mut decl_cursor = child.walk();
                for decl_child in child.children(&mut decl_cursor) {
                    if let Some(name) = self.get_declarator_name(&decl_child, source) {
                        if name == var_name && has_thread_local {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if a declaration has __thread specifier
    fn has_thread_local_specifier(&self, decl_node: &Node, source: &str) -> bool {
        let mut cursor = decl_node.walk();
        for child in decl_node.children(&mut cursor) {
            if child.kind() == "storage_class_specifier" {
                let text = get_node_text(&child, source);
                if text.trim() == "__thread" || text.trim() == "_Thread_local" {
                    return true;
                }
            }
        }
        false
    }

    /// Get the translation unit (root) node
    #[allow(dead_code)]
    fn get_translation_unit<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = Some(*node);
        while let Some(n) = current {
            if n.kind() == "translation_unit" {
                return Some(n);
            }
            current = n.parent();
        }
        None
    }

    // --- TOCTOU detection ---

    /// Check if a function name is a filesystem check function (check phase of TOCTOU)
    fn is_check_function(name: &str) -> bool {
        matches!(
            name,
            "stat" | "lstat" | "fstat" | "access" | "faccessat" | "euidaccess"
        )
    }

    /// Check if a function name is a filesystem use function (use phase of TOCTOU)
    fn is_use_function(name: &str) -> bool {
        matches!(
            name,
            "fopen"
                | "open"
                | "openat"
                | "creat"
                | "freopen"
                | "remove"
                | "unlink"
                | "rename"
                | "chmod"
                | "chown"
                | "truncate"
                | "mkdir"
                | "rmdir"
                | "link"
                | "symlink"
        )
    }

    /// Extract the path argument from a check or use function call.
    /// Returns the text of the first argument (which is the path for these functions).
    fn extract_path_arg<'a>(call_node: &Node<'a>, source: &'a str) -> Option<&'a str> {
        let args = call_node.child_by_field_name("arguments")?;
        let mut cursor = args.walk();
        for child in args.children(&mut cursor) {
            if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source));
                }
                return None; // Non-identifier first arg (e.g., string literal) — skip
            }
        }
        None
    }

    /// Walk all function definitions and check for TOCTOU patterns.
    fn check_toctou(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() == "function_definition" {
            if let Some(body) = node.child_by_field_name("body") {
                self.check_toctou_in_body(&body, source, violations);
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.check_toctou(&child, source, violations);
        }
    }

    /// Collect all call_expression nodes in order from a function body,
    /// then look for check→use pairs on the same path variable.
    fn check_toctou_in_body(&self, body: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut calls: Vec<(String, String, usize, usize)> = Vec::new(); // (func_name, path_var, line, col)
        self.collect_calls_in_order(body, source, &mut calls);

        // Look for check→use pairs on the same path variable
        for i in 0..calls.len() {
            let (ref check_func, ref check_path, _, _) = calls[i];
            if !Self::is_check_function(check_func) {
                continue;
            }
            // Look for a subsequent use function on the same path
            for (use_func, use_path, use_line, use_col) in calls.iter().skip(i + 1) {
                if Self::is_use_function(use_func) && check_path == use_path {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        line: *use_line,
                        column: *use_col,
                        file_path: String::new(),
                        message: format!(
                            "TOCTOU race condition: {}() checks '{}' then {}() uses it. \
                             The file state may change between the check and use.",
                            check_func, check_path, use_func
                        ),
                        suggestion: Some(
                            "Use atomic file operations (e.g., open() with O_CREAT|O_EXCL) \
                             instead of separate check-then-use sequences."
                                .to_string(),
                        ),
                        requires_manual_review: None,
                    });
                    break; // Only flag first use after this check
                }
            }
        }
    }

    /// Collect function calls in source order from a subtree
    fn collect_calls_in_order(
        &self,
        node: &Node,
        source: &str,
        calls: &mut Vec<(String, String, usize, usize)>,
    ) {
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);
                if Self::is_check_function(func_name) || Self::is_use_function(func_name) {
                    if let Some(path_var) = Self::extract_path_arg(node, source) {
                        calls.push((
                            func_name.to_string(),
                            path_var.to_string(),
                            node.start_position().row + 1,
                            node.start_position().column + 1,
                        ));
                    }
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.collect_calls_in_order(&child, source, calls);
        }
    }
}
