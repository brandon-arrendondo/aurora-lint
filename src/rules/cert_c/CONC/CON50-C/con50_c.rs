// CON50-C: Do not destroy a mutex while it is locked
//
// This rule detects when a mutex with automatic storage duration is passed
// to threads and may be destroyed while still locked (because threads aren't
// joined before function exit).
//
// Detection strategy:
// 1. Find functions with local mutex variables (automatic storage)
// 2. Check if mutex is passed to threads (thread creation calls)
// 3. Verify if all threads are joined before function exit
// 4. Flag violation if mutex may be destroyed while threads are still running

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use tree_sitter::Node;

pub struct Con50C;

impl Con50C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Con50C
    }

    /// Check a node and all its descendants for violations
    fn check_node<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for function definitions
        if node.kind() == "function_definition" {
            self.check_function(node, source, violations);
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_node(&child, source, violations);
            }
        }
    }

    /// Check a function for mutex lifetime issues
    fn check_function<'a>(
        &self,
        func_node: &Node<'a>,
        source: &'a str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Find local mutex variables
        let local_mutexes = self.find_local_mutexes(func_node, source);

        if local_mutexes.is_empty() {
            return;
        }

        // For each local mutex, check if it's used with threads
        for mutex_name in &local_mutexes {
            let thread_vars = self.find_threads_using_mutex(func_node, source, mutex_name);

            if !thread_vars.is_empty() {
                // Check if all threads are joined before function exit
                if !self.all_threads_joined(func_node, source, &thread_vars) {
                    // Find the mutex declaration for reporting
                    if let Some(decl_node) =
                        self.find_mutex_declaration(func_node, source, mutex_name)
                    {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            line: decl_node.start_position().row + 1,
                            column: decl_node.start_position().column + 1,
                            message: format!(
                                "Mutex '{}' has automatic storage duration and may be destroyed while threads are still running (threads not joined before function exit)",
                                mutex_name
                            ),
                            severity: self.severity(),
                            file_path: String::new(),
                            suggestion: Some(format!(
                                "Either make '{}' static/global, or join all threads before function returns",
                                mutex_name
                            )),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }
    }

    /// Find all local mutex variables in a function
    fn find_local_mutexes<'a>(&self, func_node: &Node<'a>, source: &'a str) -> Vec<String> {
        let mut mutexes = Vec::new();

        if let Some(body) = func_node.child_by_field_name("body") {
            self.collect_mutex_declarations(&body, source, &mut mutexes, false);
        }

        mutexes
    }

    /// Recursively collect mutex declarations
    fn collect_mutex_declarations<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        mutexes: &mut Vec<String>,
        is_static: bool,
    ) {
        if node.kind() == "declaration" {
            // Check for static storage class
            let mut is_static_decl = is_static;

            // Look for storage class specifier
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "storage_class_specifier" {
                        let specifier = get_node_text(&child, source);
                        if specifier == "static" || specifier == "extern" {
                            is_static_decl = true;
                        }
                    }
                }
            }

            // Check if type is a mutex
            if let Some(type_node) = node.child_by_field_name("type") {
                let type_text = get_node_text(&type_node, source);

                // Check for mutex types (C++: std::mutex, pthread: pthread_mutex_t, C11: mtx_t)
                if type_text.contains("mutex") || type_text.contains("mtx_t") {
                    // Only collect if not static
                    if !is_static_decl {
                        // Find the identifier
                        for i in 0..node.child_count() {
                            if let Some(child) = node.child(i) {
                                if let Some(id) = self.get_declarator_id(&child, source) {
                                    mutexes.push(id.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_mutex_declarations(&child, source, mutexes, is_static);
            }
        }
    }

    /// Get identifier from a declarator
    fn get_declarator_id<'a>(&self, node: &Node<'a>, source: &'a str) -> Option<&'a str> {
        match node.kind() {
            "identifier" => Some(get_node_text(node, source)),
            "init_declarator" => {
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    self.get_declarator_id(&declarator, source)
                } else {
                    None
                }
            }
            "pointer_declarator" | "array_declarator" | "function_declarator" => {
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    self.get_declarator_id(&declarator, source)
                } else {
                    None
                }
            }
            _ => {
                // Recurse to find identifier
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if let Some(id) = self.get_declarator_id(&child, source) {
                            return Some(id);
                        }
                    }
                }
                None
            }
        }
    }

    /// Find threads that are created with this mutex
    fn find_threads_using_mutex<'a>(
        &self,
        func_node: &Node<'a>,
        source: &'a str,
        mutex_name: &str,
    ) -> Vec<String> {
        let mut thread_vars = Vec::new();

        if let Some(body) = func_node.child_by_field_name("body") {
            self.collect_thread_creations(&body, source, mutex_name, &mut thread_vars);
        }

        thread_vars
    }

    /// Collect thread variables that receive the mutex
    fn collect_thread_creations<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        mutex_name: &str,
        thread_vars: &mut Vec<String>,
    ) {
        // Look for thread creation patterns:
        // - std::thread threads[N] or std::thread t;
        // - threads[i] = std::thread(func, ..., &mutex)
        // - pthread_create(&thread, NULL, func, &mutex)
        // - thrd_create(&thread, func, &mutex)

        if node.kind() == "assignment_expression" || node.kind() == "init_declarator" {
            // Check if right side creates thread with mutex
            if let Some(right) = node.child_by_field_name("right") {
                let right_text = get_node_text(&right, source);

                // Check if mutex is passed to thread
                if right_text.contains(mutex_name)
                    && (right_text.contains("std::thread") || right_text.contains("thread("))
                {
                    // Get the thread variable name
                    if let Some(left) = node.child_by_field_name("left") {
                        if let Some(thread_var) = self.extract_thread_var_name(&left, source) {
                            thread_vars.push(thread_var.to_string());
                        }
                    }
                }
            }

            // Also check init declarator value
            if let Some(value) = node.child_by_field_name("value") {
                let value_text = get_node_text(&value, source);
                if value_text.contains(mutex_name)
                    && (value_text.contains("std::thread") || value_text.contains("thread("))
                {
                    if let Some(declarator) = node.child_by_field_name("declarator") {
                        if let Some(thread_var) = self.get_declarator_id(&declarator, source) {
                            thread_vars.push(thread_var.to_string());
                        }
                    }
                }
            }
        }

        // Look for pthread_create or thrd_create calls
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);

                if func_name == "pthread_create" || func_name == "thrd_create" {
                    // Check if mutex is passed in arguments
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let args_text = get_node_text(&args, source);
                        if args_text.contains(mutex_name) {
                            // Extract thread variable (first argument)
                            if let Some(thread_arg) = self.get_first_argument(&args, source) {
                                thread_vars.push(thread_arg.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_thread_creations(&child, source, mutex_name, thread_vars);
            }
        }
    }

    /// Extract thread variable name from subscript or identifier
    fn extract_thread_var_name<'a>(&self, node: &Node<'a>, source: &'a str) -> Option<&'a str> {
        match node.kind() {
            "identifier" => Some(get_node_text(node, source)),
            "subscript_expression" => {
                // threads[i] -> get "threads"
                if let Some(array) = node.child_by_field_name("argument") {
                    return self.extract_thread_var_name(&array, source);
                }
                None
            }
            _ => {
                // Try to find identifier in children
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "identifier" {
                            return Some(get_node_text(&child, source));
                        }
                    }
                }
                None
            }
        }
    }

    /// Get first argument from argument list
    fn get_first_argument<'a>(&self, args_node: &Node<'a>, source: &'a str) -> Option<&'a str> {
        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    // Found first argument
                    let arg_text = get_node_text(&child, source);
                    // Extract variable name (remove & or *)
                    return Some(
                        arg_text
                            .trim_start_matches('&')
                            .trim_start_matches('*')
                            .trim(),
                    );
                }
            }
        }
        None
    }

    /// Check if all threads are joined before function exit
    fn all_threads_joined<'a>(
        &self,
        func_node: &Node<'a>,
        source: &'a str,
        thread_vars: &[String],
    ) -> bool {
        // Look for .join() calls or pthread_join/thrd_join for each thread
        let mut joined_threads = Vec::new();

        if let Some(body) = func_node.child_by_field_name("body") {
            self.collect_joined_threads(&body, source, &mut joined_threads);
        }

        // Check if all threads are joined
        for thread_var in thread_vars {
            // Extract base name (threads[i] -> threads)
            let base_name = thread_var.split('[').next().unwrap_or(thread_var);

            if !joined_threads.iter().any(|j| j.contains(base_name)) {
                return false;
            }
        }

        true
    }

    /// Collect all thread join operations
    fn collect_joined_threads<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        joined: &mut Vec<String>,
    ) {
        // Look for .join() calls or pthread_join/thrd_join
        if node.kind() == "call_expression" {
            let call_text = get_node_text(node, source);

            if call_text.contains(".join()")
                || call_text.contains("pthread_join")
                || call_text.contains("thrd_join")
            {
                joined.push(call_text.to_string());
            }
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_joined_threads(&child, source, joined);
            }
        }
    }

    /// Find mutex declaration node
    fn find_mutex_declaration<'a>(
        &self,
        func_node: &Node<'a>,
        source: &'a str,
        mutex_name: &str,
    ) -> Option<Node<'a>> {
        if let Some(body) = func_node.child_by_field_name("body") {
            return self.find_declaration_by_name(&body, source, mutex_name);
        }
        None
    }

    /// Recursively find declaration by name
    fn find_declaration_by_name<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        name: &str,
    ) -> Option<Node<'a>> {
        if node.kind() == "declaration" {
            // Check if this declares our variable
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if let Some(id) = self.get_declarator_id(&child, source) {
                        if id == name {
                            return Some(*node);
                        }
                    }
                }
            }
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(found) = self.find_declaration_by_name(&child, source, name) {
                    return Some(found);
                }
            }
        }

        None
    }
}

impl CertRule for Con50C {
    fn rule_id(&self) -> &'static str {
        "CON50-C"
    }

    fn description(&self) -> &'static str {
        "Do not destroy a mutex while it is locked"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "CON50-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}
