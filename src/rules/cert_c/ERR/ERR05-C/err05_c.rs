//! ERR05-C: Application-independent code should provide error detection without dictating error handling
//!
//! Application-independent code (libraries, reusable modules) must detect errors and
//! report them to calling code rather than dictating error handling by calling abort(),
//! exit(), or _Exit(). The calling application should decide how to handle errors.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void library_function(void) {
//!     if (something_bad_happens) {
//!         fprintf(stderr, "Error occurred\n");
//!         abort();  // Dictates error handling - violates rule
//!     }
//! }
//!
//! int process_data(const char *data) {
//!     if (data == NULL) {
//!         exit(EXIT_FAILURE);  // Library shouldn't call exit()
//!     }
//!     // ... processing
//! }
//! ```
//!
//! **Compliant (return value):**
//! ```c
//! errno_t library_function(void) {
//!     if (something_bad_happens) {
//!         return ERROR_CODE;  // Let caller decide how to handle
//!     }
//!     return 0;  // Success
//! }
//!
//! int process_data(const char *data) {
//!     if (data == NULL) {
//!         return -1;  // Report error via return value
//!     }
//!     // ... processing
//!     return 0;
//! }
//! ```
//!
//! **Compliant (address argument):**
//! ```c
//! void library_function(errno_t *err) {
//!     if (something_bad_happens) {
//!         *err = ERROR_CODE;
//!         return;
//!     }
//!     *err = 0;
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Detect calls to abort(), exit(), or _Exit() within functions
//! - These functions should only be called from main() or application entry points
//! - Library/reusable code should use return values or error parameters instead

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Err05C;

impl CertRule for Err05C {
    fn rule_id(&self) -> &'static str {
        "ERR05-C"
    }

    fn description(&self) -> &'static str {
        "Application-independent code should provide error detection without dictating error handling"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ERR05-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Err05C {
    /// Check nodes for abort/exit calls
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check function definitions (not main)
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            if !self.is_main_function(&func, source) {
                self.check_function_for_termination_calls(&func, source, violations);
            }
        }
    }

    /// Check if this is the main() function
    fn is_main_function(&self, func_node: &Node, source: &str) -> bool {
        if let Some(declarator) = func_node.child_by_field_name("declarator") {
            let func_name = self.get_function_name(&declarator, source);
            func_name == "main"
        } else {
            false
        }
    }

    /// Get function name from declarator
    fn get_function_name(&self, declarator: &Node, source: &str) -> String {
        match declarator.kind() {
            "function_declarator" => {
                if let Some(inner) = declarator.child_by_field_name("declarator") {
                    return self.get_function_name(&inner, source);
                }
            }
            "identifier" => {
                return get_node_text(declarator, source).to_string();
            }
            _ => {
                // Try to find identifier in children
                for i in 0..declarator.child_count() {
                    if let Some(child) = declarator.child(i) {
                        if child.kind() == "identifier" {
                            return get_node_text(&child, source).to_string();
                        }
                        let name = self.get_function_name(&child, source);
                        if !name.is_empty() && name != "unknown" {
                            return name;
                        }
                    }
                }
            }
        }
        String::from("unknown")
    }

    /// Check function body for calls to abort(), exit(), or _Exit()
    fn check_function_for_termination_calls(
        &self,
        func_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let func_name = if let Some(declarator) = func_node.child_by_field_name("declarator") {
            self.get_function_name(&declarator, source)
        } else {
            String::from("unknown")
        };

        if let Some(body) = func_node.child_by_field_name("body") {
            self.scan_for_termination_calls(&body, source, &func_name, violations);
        }
    }

    /// Scan for termination function calls
    fn scan_for_termination_calls(
        &self,
        node: &Node,
        source: &str,
        func_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let called_func = get_node_text(&function, source);

                if self.is_termination_function(&called_func) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        message: format!(
                            "Function '{}' calls '{}', which dictates error handling. \
                             Application-independent code should report errors to the caller \
                             (via return values, error parameters, or error indicators) rather \
                             than terminating the program.",
                            func_name, called_func
                        ),
                        severity: self.severity(),
                        line: call.start_position().row + 1,
                        column: call.start_position().column + 1,
                        file_path: String::new(),
                        suggestion: Some(format!(
                            "Replace '{}' with error reporting via return value (e.g., 'return ERROR_CODE;'), \
                             error parameter (e.g., '*err = ERROR_CODE;'), or global error indicator",
                            called_func
                        )),
                        requires_manual_review: None,
                    });
                }
            }
        }
    }

    /// Check if function is a termination function
    fn is_termination_function(&self, name: &str) -> bool {
        matches!(name, "abort" | "exit" | "_Exit" | "quick_exit")
    }
}
