//! SIG01-C: Understand implementation-specific details regarding signal handler persistence
//!
//! The signal() function has implementation-defined behavior regarding signal handler
//! persistence. On some systems (e.g., many UNIX variants), signal handlers persist
//! after being called. On others (e.g., Windows), handlers are reset to default after
//! each signal delivery, requiring reinstallation.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void handler(int sig) {
//!     /* Handler logic */
//! }
//!
//! int main(void) {
//!     signal(SIGINT, handler);  // VIOLATION: Implementation-defined persistence
//!     while (1) { /* ... */ }
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! void handler(int sig) {
//!     /* Handler logic */
//! }
//!
//! int main(void) {
//!     struct sigaction sa;
//!     sa.sa_handler = handler;
//!     sa.sa_flags = 0;  // Explicit control over handler persistence
//!     sigemptyset(&sa.sa_mask);
//!     sigaction(SIGINT, &sa, NULL);  // OK: Well-defined behavior
//!     while (1) { /* ... */ }
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Sig01C;

impl CertRule for Sig01C {
    fn rule_id(&self) -> &'static str {
        "SIG01-C"
    }

    fn description(&self) -> &'static str {
        "Understand implementation-specific details regarding signal handler persistence"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "SIG01-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Sig01C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for signal() function calls
        for node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                // Detect use of signal() function
                if func_name == "signal" {
                    // Check if this is a signal handler registration (not a query like signal(sig, SIG_IGN))
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let arg_list = self.get_arguments(&args, source);

                        // signal() takes 2 arguments: signal number and handler
                        if arg_list.len() >= 2 {
                            let handler_arg = arg_list[1].trim();

                            // Only flag if registering an actual handler (not SIG_DFL, SIG_IGN, etc.)
                            if !handler_arg.starts_with("SIG_")
                                && handler_arg != "NULL"
                                && handler_arg != "0"
                            {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Low,
                                    message: "Use of signal() has implementation-defined behavior regarding handler persistence. Consider using sigaction() for portable behavior.".to_string(),
                                    file_path: String::new(),
                                    line: node.start_position().row + 1,
                                    column: node.start_position().column + 1,
                                    suggestion: Some(
                                        "Replace signal() with sigaction() to ensure consistent, well-defined behavior across platforms. sigaction() provides explicit control over handler persistence via the SA_RESETHAND flag.".to_string()
                                    ),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Extract argument strings from an argument_list node
    fn get_arguments(&self, args_node: &Node, source: &str) -> Vec<String> {
        let mut arguments = Vec::new();

        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                let kind = child.kind();
                // Skip punctuation nodes (commas, parentheses)
                if kind != "," && kind != "(" && kind != ")" {
                    let arg_text = get_node_text(&child, source).to_string();
                    arguments.push(arg_text);
                }
            }
        }

        arguments
    }
}
