//! SIG35-C: Do not return from a computational exception signal handler
//!
//! According to the C Standard, if a signal handler returns after being invoked
//! for a computational exception (SIGFPE, SIGILL, SIGSEGV, SIGBUS), the behavior
//! is undefined. The only safe approach is to call abort(), quick_exit(), or _Exit().
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void handler(int sig) {
//!     // Attempt to fix error and return
//!     if (denom == 0) {
//!         denom = 1;  // VIOLATION: Cannot return from SIGFPE handler
//!     }
//! }  // VIOLATION: Returns from computational exception handler
//! ```
//!
//! **Compliant:**
//! ```c
//! void handler(int sig) {
//!     abort();  // OK: Terminates instead of returning
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Sig35C;

impl CertRule for Sig35C {
    fn rule_id(&self) -> &'static str {
        "SIG35-C"
    }

    fn description(&self) -> &'static str {
        "Do not return from a computational exception signal handler"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "SIG35-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Find all signal handlers registered for computational exception signals
        let computational_handlers = self.find_computational_exception_handlers(node, source);

        // Check each handler for improper returns
        self.check_node(node, source, &computational_handlers, &mut violations);

        violations
    }
}

impl Sig35C {
    /// Find all handlers registered for computational exception signals
    /// (SIGFPE, SIGILL, SIGSEGV, SIGBUS)
    fn find_computational_exception_handlers(
        &self,
        node: &Node,
        source: &str,
    ) -> HashMap<String, String> {
        let mut handlers = HashMap::new();
        self.collect_computational_handlers(node, source, &mut handlers);
        handlers
    }

    fn collect_computational_handlers(
        &self,
        node: &Node,
        source: &str,
        handlers: &mut HashMap<String, String>,
    ) {
        for n in
            query::find_descendants_of_kinds(*node, &["call_expression", "assignment_expression"])
        {
            // Look for signal(SIGXXX, handler_func) calls
            if n.kind() == "call_expression" {
                if let Some(function) = n.child_by_field_name("function") {
                    let func_name = get_node_text(&function, source);

                    if func_name == "signal" {
                        // Get the signal type and handler function name
                        if let Some(args) = n.child_by_field_name("arguments") {
                            let arg_list = self.get_arguments(&args, source);

                            // For signal(sig, handler), check if sig is computational exception
                            if arg_list.len() >= 2 {
                                let signal_name = arg_list[0].trim();
                                let handler_name = arg_list[1].trim();

                                if self.is_computational_exception_signal(signal_name) {
                                    // Skip SIG_IGN, SIG_DFL, SIG_ERR, NULL
                                    if !handler_name.starts_with("SIG_")
                                        && handler_name != "NULL"
                                        && handler_name != "0"
                                        && !handler_name.is_empty()
                                    {
                                        // Map handler name to signal name
                                        handlers.insert(
                                            handler_name.to_string(),
                                            signal_name.to_string(),
                                        );
                                    }
                                }
                            }
                        }
                    }

                    if func_name == "sigaction" {
                        // For sigaction(signal, &sa, NULL), track the signal and struct
                        if let Some(args) = n.child_by_field_name("arguments") {
                            let arg_list = self.get_arguments(&args, source);

                            if arg_list.len() >= 2 {
                                let signal_name = arg_list[0].trim();
                                if self.is_computational_exception_signal(signal_name) {
                                    // Try to find sa_handler or sa_sigaction assignments
                                    // Look backwards for struct assignments
                                    self.collect_sigaction_handlers(
                                        &n,
                                        source,
                                        signal_name,
                                        handlers,
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // Look for struct field assignments like sa.sa_sigaction = handler
            if n.kind() == "assignment_expression" {
                if let (Some(left), Some(right)) = (
                    n.child_by_field_name("left"),
                    n.child_by_field_name("right"),
                ) {
                    let left_text = get_node_text(&left, source);
                    if left_text.ends_with(".sa_handler") || left_text.ends_with(".sa_sigaction") {
                        let handler_name = get_node_text(&right, source);
                        if !handler_name.starts_with("SIG_")
                            && handler_name != "NULL"
                            && !handler_name.is_empty()
                        {
                            // We'll associate this later when we see sigaction() call
                            // For now, just note it might be a handler
                            // This is tricky without full data flow analysis
                            // For a simple approach, we'll mark any function assigned to sa_* as suspicious
                        }
                    }
                }
            }
        }
    }

    fn collect_sigaction_handlers(
        &self,
        sigaction_node: &Node,
        source: &str,
        signal_name: &str,
        handlers: &mut HashMap<String, String>,
    ) {
        // Simple heuristic: look in the parent compound statement for sa.sa_handler assignments
        let mut current = sigaction_node.parent();
        while let Some(parent) = current {
            if parent.kind() == "compound_statement" || parent.kind() == "function_definition" {
                // Search this scope for field assignments
                self.find_handler_assignments(&parent, source, signal_name, handlers);
                break;
            }
            current = parent.parent();
        }
    }

    fn find_handler_assignments(
        &self,
        scope: &Node,
        source: &str,
        signal_name: &str,
        handlers: &mut HashMap<String, String>,
    ) {
        for assign in query::find_descendants_of_kind(*scope, "assignment_expression") {
            if let (Some(left), Some(right)) = (
                assign.child_by_field_name("left"),
                assign.child_by_field_name("right"),
            ) {
                let left_text = get_node_text(&left, source);
                if left_text.ends_with(".sa_handler") || left_text.ends_with(".sa_sigaction") {
                    let handler_name = get_node_text(&right, source).trim().to_string();
                    if !handler_name.starts_with("SIG_")
                        && handler_name != "NULL"
                        && !handler_name.is_empty()
                    {
                        handlers.insert(handler_name, signal_name.to_string());
                    }
                }
            }
        }
    }

    /// Check if a signal is a computational exception signal
    fn is_computational_exception_signal(&self, signal_name: &str) -> bool {
        const COMPUTATIONAL_SIGNALS: &[&str] =
            &["SIGFPE", "SIGILL", "SIGSEGV", "SIGBUS", "SIGTRAP"];
        COMPUTATIONAL_SIGNALS.contains(&signal_name)
    }

    /// Get argument strings from an argument_list node
    fn get_arguments(&self, args_node: &Node, source: &str) -> Vec<String> {
        let mut arguments = Vec::new();

        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                let kind = child.kind();
                if kind != "," && kind != "(" && kind != ")" {
                    let arg_text = get_node_text(&child, source).to_string();
                    arguments.push(arg_text);
                }
            }
        }

        arguments
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        handlers: &HashMap<String, String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if this is a function definition that's a computational exception handler
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(declarator) = func.child_by_field_name("declarator") {
                if let Some(func_name) = self.get_function_name_text(&declarator, source) {
                    if let Some(signal_name) = handlers.get(&func_name) {
                        // This is a computational exception handler - check for returns
                        if let Some(body) = func.child_by_field_name("body") {
                            self.check_handler_for_return(
                                &body,
                                source,
                                &func_name,
                                signal_name,
                                violations,
                            );
                        }
                    }
                }
            }
        }
    }

    fn get_function_name_text(&self, declarator: &Node, source: &str) -> Option<String> {
        // Handle function_declarator -> identifier
        if declarator.kind() == "function_declarator" {
            if let Some(inner) = declarator.child_by_field_name("declarator") {
                let text = get_node_text(&inner, source);
                return Some(text.to_string());
            }
        }

        // Handle pointer_declarator wrapping
        if declarator.kind() == "pointer_declarator" {
            if let Some(inner) = declarator.child_by_field_name("declarator") {
                return self.get_function_name_text(&inner, source);
            }
        }

        // If it's already an identifier
        if declarator.kind() == "identifier" {
            let text = get_node_text(&declarator, source);
            return Some(text.to_string());
        }

        None
    }

    fn check_handler_for_return(
        &self,
        body: &Node,
        source: &str,
        handler_name: &str,
        signal_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if the handler has ANY return statement (explicit or implicit)
        // In a computational exception handler, ANY return is a violation
        let has_explicit_return = self.has_return_statement(body, source);
        let has_termination_calls = self.contains_termination_call(body, source);
        let has_guaranteed_termination = self.all_paths_terminate(body, source);

        // If there's an explicit return, it's always a violation
        if has_explicit_return {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::Low,
                message: format!(
                    "Signal handler '{}' for computational exception '{}' may return normally, causing undefined behavior",
                    handler_name, signal_name
                ),
                file_path: String::new(),
                line: body.start_position().row + 1,
                column: body.start_position().column + 1,
                suggestion: Some(
                    "Call abort(), quick_exit(), or _Exit() instead of returning from a computational exception signal handler".to_string()
                ),
                ..Default::default()
            });
            return;
        }

        // If no explicit return AND handler contains termination calls, likely OK
        // (Heuristic: if the handler calls termination functions and doesn't explicitly return, assume it's compliant)
        if !has_termination_calls && !has_guaranteed_termination {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::Low,
                message: format!(
                    "Signal handler '{}' for computational exception '{}' may return normally, causing undefined behavior",
                    handler_name, signal_name
                ),
                file_path: String::new(),
                line: body.start_position().row + 1,
                column: body.start_position().column + 1,
                suggestion: Some(
                    "Call abort(), quick_exit(), or _Exit() instead of returning from a computational exception signal handler".to_string()
                ),
                ..Default::default()
            });
        }
    }

    /// Check if the handler contains any termination calls (abort, _Exit, quick_exit, exit)
    fn contains_termination_call(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(function) = n.child_by_field_name("function") else {
                return false;
            };
            let func_name = get_node_text(&function, source);
            func_name == "abort"
                || func_name == "_Exit"
                || func_name == "quick_exit"
                || func_name == "exit"
        })
        .is_some()
    }

    /// Check if there are any explicit return statements
    fn has_return_statement(&self, node: &Node, _source: &str) -> bool {
        query::find_first_descendant(*node, |n| n.kind() == "return_statement").is_some()
    }

    /// Check if ALL code paths are guaranteed to call a termination function
    /// This is a simplified check - returns true only if the function body
    /// definitely ends with a termination call or infinite loop
    fn all_paths_terminate(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "compound_statement" {
            // Check if the last meaningful statement is a termination call
            let mut last_stmt = None;
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    // Skip braces and whitespace
                    if child.kind() != "{" && child.kind() != "}" && child.kind() != "comment" {
                        last_stmt = Some(child);
                    }
                }
            }

            if let Some(stmt) = last_stmt {
                // Check if it's a termination call
                if self.is_termination_statement(&stmt, source) {
                    return true;
                }
                // Check if it's an infinite loop (while(1), for(;;))
                if self.is_infinite_loop(&stmt, source) {
                    return true;
                }
                // Check if it's a switch statement where all paths terminate
                if stmt.kind() == "switch_statement" {
                    if self.switch_all_paths_terminate(&stmt, source) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if a switch statement has all paths terminating
    fn switch_all_paths_terminate(&self, switch_node: &Node, source: &str) -> bool {
        // Find the compound_statement body of the switch
        if let Some(body) = switch_node.child_by_field_name("body") {
            // Check if all case/default labels end with termination
            let cases = self.get_switch_cases(&body, source);

            if cases.is_empty() {
                return false;
            }

            // Check each case to see if it terminates
            for case_body in cases {
                if !self.case_terminates(&case_body, source) {
                    return false;
                }
            }

            return true;
        }

        false
    }

    /// Get all the case bodies from a switch compound statement
    fn get_switch_cases<'a>(&self, body: &'a Node, _source: &str) -> Vec<Node<'a>> {
        let mut cases = Vec::new();
        let mut current_case_stmts = Vec::new();

        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                match child.kind() {
                    "case_statement" | "default_statement" => {
                        // Start a new case, save previous one if any
                        if !current_case_stmts.is_empty() {
                            // We'll return the statements as a group
                            // For simplicity, we'll just check the last one
                        }
                        current_case_stmts.clear();
                    }
                    _ => {
                        // Accumulate statements for current case
                        if child.kind() != "{" && child.kind() != "}" {
                            current_case_stmts.push(child);
                        }
                    }
                }
            }
        }

        // Simplified: just collect all non-label statements in switch
        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                if child.kind() != "{"
                    && child.kind() != "}"
                    && child.kind() != "case_statement"
                    && child.kind() != "default_statement"
                    && child.kind() != "break_statement"
                {
                    cases.push(child);
                }
            }
        }

        cases
    }

    /// Check if a case body ends with termination
    fn case_terminates(&self, case_stmt: &Node, source: &str) -> bool {
        // Check if this statement is or contains a termination call
        if self.is_termination_statement(case_stmt, source) {
            return true;
        }

        // If it's a compound statement, check its last statement
        if case_stmt.kind() == "compound_statement" {
            return self.all_paths_terminate(case_stmt, source);
        }

        false
    }

    fn is_infinite_loop(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "while_statement" {
            if let Some(condition) = node.child_by_field_name("condition") {
                let cond_text = get_node_text(&condition, source).trim();
                if cond_text == "(1)" || cond_text == "(true)" {
                    return true;
                }
            }
        }

        if node.kind() == "for_statement" {
            // Check for for(;;) pattern
            let text = get_node_text(node, source);
            if text.starts_with("for") && text.contains("(;;)") {
                return true;
            }
        }

        false
    }

    fn is_termination_statement(&self, node: &Node, source: &str) -> bool {
        // Check if node is a call to abort, _Exit, or quick_exit
        if node.kind() == "expression_statement" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "call_expression" {
                        if let Some(function) = child.child_by_field_name("function") {
                            let func_name = get_node_text(&function, source);
                            if func_name == "abort"
                                || func_name == "_Exit"
                                || func_name == "quick_exit"
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }
}
