//! ENV32-C: All exit handlers must return normally
//!
//! Exit handlers registered with atexit() or at_quick_exit() must terminate
//! by returning. Calling exit(), _Exit(), quick_exit(), longjmp(), or abort()
//! from within an exit handler causes undefined behavior.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void exit_handler(void) {
//!     exit(0);  // Undefined behavior
//! }
//! atexit(exit_handler);
//! ```
//!
//! **Compliant:**
//! ```c
//! void exit_handler(void) {
//!     // cleanup
//!     return;
//! }
//! atexit(exit_handler);
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Env32C;

impl CertRule for Env32C {
    fn rule_id(&self) -> &'static str {
        "ENV32-C"
    }

    fn description(&self) -> &'static str {
        "All exit handlers must return normally"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ENV32-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: find exit handler registrations
        let mut exit_handlers: HashSet<String> = HashSet::new();
        self.find_exit_handler_registrations(node, source, &mut exit_handlers);

        // Second pass: check each registered handler for non-returning calls
        if !exit_handlers.is_empty() {
            self.check_handler_bodies(node, source, &exit_handlers, &mut violations);
        }

        violations
    }
}

impl Env32C {
    /// Find functions registered as exit handlers
    fn find_exit_handler_registrations(
        &self,
        node: &Node,
        source: &str,
        handlers: &mut HashSet<String>,
    ) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                // Check for atexit() or at_quick_exit() calls
                if func_name == "atexit" || func_name == "at_quick_exit" {
                    if let Some(args) = call.child_by_field_name("arguments") {
                        // Get the first argument (the handler function)
                        for i in 0..args.child_count() {
                            if let Some(child) = args.child(i) {
                                let kind = child.kind();
                                if kind != "," && kind != "(" && kind != ")" {
                                    let handler_name = get_node_text(&child, source).to_string();
                                    handlers.insert(handler_name);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check function bodies for non-returning calls
    fn check_handler_bodies(
        &self,
        node: &Node,
        source: &str,
        handlers: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(declarator) = func.child_by_field_name("declarator") {
                let func_name = self.get_function_name(&declarator, source);

                if handlers.contains(&func_name) {
                    // This is an exit handler, check its body
                    if let Some(body) = func.child_by_field_name("body") {
                        self.check_for_non_returning_calls(&body, source, &func_name, violations);
                    }
                }
            }
        }
    }

    /// Get function name from declarator
    fn get_function_name(&self, declarator: &Node, source: &str) -> String {
        if declarator.kind() == "identifier" {
            return get_node_text(declarator, source).to_string();
        }

        // Check for function declarator
        if declarator.kind() == "function_declarator" {
            if let Some(name_node) = declarator.child_by_field_name("declarator") {
                return get_node_text(&name_node, source).to_string();
            }
        }

        // Recurse to find identifier
        for i in 0..declarator.child_count() {
            if let Some(child) = declarator.child(i) {
                let name = self.get_function_name(&child, source);
                if !name.is_empty() {
                    return name;
                }
            }
        }

        String::new()
    }

    /// Check for calls that prevent normal return
    fn check_for_non_returning_calls(
        &self,
        node: &Node,
        source: &str,
        handler_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if self.is_non_returning_function(&func_name) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        message: format!(
                            "Exit handler '{}' calls '{}' which prevents normal return. \
                             Exit handlers must return normally to ensure all cleanup \
                             actions complete.",
                            handler_name, func_name
                        ),
                        severity: self.severity(),
                        line: call.start_position().row + 1,
                        column: call.start_position().column + 1,
                        file_path: String::new(),
                        suggestion: Some(format!(
                            "Remove the call to '{}' and ensure the handler returns normally",
                            func_name
                        )),
                        requires_manual_review: None,
                    });
                }
            }
        }
    }

    /// Check if a function prevents normal return
    fn is_non_returning_function(&self, name: &str) -> bool {
        matches!(
            name,
            "exit" | "_Exit" | "quick_exit" | "abort" | "longjmp" | "_longjmp"
        )
    }
}
