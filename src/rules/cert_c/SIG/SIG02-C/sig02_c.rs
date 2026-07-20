//! SIG02-C: Avoid using signals to implement normal functionality
//!
//! This rule detects when signals are misused for normal program functionality
//! such as inter-thread communication, timing/scheduling, or control flow,
//! instead of being reserved for abnormal events.
//!
//! ## Non-compliant example:
//!
//! ```c
//! // Using signals for inter-thread communication
//! void thread_notify(pid_t pid) {
//!     kill(pid, SIGUSR1);  // Misusing signal for normal communication
//! }
//!
//! void handler(int signum) {
//!     // Complex processing in signal handler
//!     process_data();
//!     update_state();
//! }
//!
//! signal(SIGUSR1, handler);
//! signal(SIGALRM, timer_handler);  // Using signals for timing
//! signal(SIGPIPE, connection_handler);  // Using signals for normal events
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! // Use proper synchronization primitives
//! pthread_mutex_t mutex;
//! pthread_cond_t cond;
//!
//! void thread_notify() {
//!     pthread_mutex_lock(&mutex);
//!     pthread_cond_signal(&cond);
//!     pthread_mutex_unlock(&mutex);
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{get_node_text, get_sanitized_node_text};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Sig02C;

/// Signals commonly misused for normal functionality
const NORMAL_USE_SIGNALS: &[&str] = &[
    "SIGUSR1",
    "SIGUSR2",
    "SIGALRM", // Timer/scheduling
    "SIGPIPE", // Connection handling
    "SIGURG",  // Out-of-band data
    "SIGVTALRM",
    "SIGPROF",
    "SIGIO",
    "SIGPOLL",
];

impl Sig02C {
    pub fn new() -> Self {
        Self
    }

    /// Check if a signal name suggests normal functionality use
    fn is_normal_use_signal(&self, signal_name: &str) -> bool {
        NORMAL_USE_SIGNALS.iter().any(|s| signal_name.contains(s))
    }

    /// Check for kill() calls with signals used for normal functionality
    fn check_kill_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() != "call_expression" {
            return;
        }

        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            if function_name == "kill" {
                if let Some(args_node) = node.child_by_field_name("arguments") {
                    let args_text = get_node_text(&args_node, source);

                    if self.is_normal_use_signal(args_text) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: "Use of kill() with signal for normal inter-process communication instead of abnormal events. Consider using proper IPC mechanisms like message queues, pipes, or condition variables.".to_string(),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(
                                "Replace signal-based communication with appropriate IPC mechanisms: pthread_cond_t for threads, message queues for processes, or other synchronization primitives."
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Check for signal() or sigaction() calls registering handlers for signals
    /// that suggest normal functionality usage
    fn check_signal_registration(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() != "call_expression" {
            return;
        }

        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            if function_name == "signal" || function_name == "sigaction" {
                if let Some(args_node) = node.child_by_field_name("arguments") {
                    let args_text = get_node_text(&args_node, source);

                    if self.is_normal_use_signal(args_text) {
                        let signal_type = if args_text.contains("SIGALRM")
                            || args_text.contains("SIGVTALRM")
                            || args_text.contains("SIGPROF")
                        {
                            "timing/scheduling"
                        } else if args_text.contains("SIGPIPE") || args_text.contains("SIGURG") {
                            "connection/data handling"
                        } else if args_text.contains("SIGIO") || args_text.contains("SIGPOLL") {
                            "I/O notification"
                        } else {
                            "inter-process communication"
                        };

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "Registering signal handler with {}() for {}. This suggests using signals for normal functionality instead of abnormal events.",
                                function_name, signal_type
                            ),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(
                                "Signals should be reserved for abnormal events. For normal functionality, use proper alternatives: timers (timer_create), threading (pthread), or I/O multiplexing (select/poll/epoll)."
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Check for raise() calls with signals used for normal functionality
    fn check_raise_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() != "call_expression" {
            return;
        }

        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            if function_name == "raise" {
                if let Some(args_node) = node.child_by_field_name("arguments") {
                    let args_text = get_node_text(&args_node, source);

                    if self.is_normal_use_signal(args_text) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: "Use of raise() with signal for normal control flow instead of abnormal events.".to_string(),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(
                                "Avoid using signals for normal program flow. Use function calls, return values, or proper control structures instead."
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Check for functions that appear to be signal handlers doing complex/unsafe work
    /// This specifically looks for K&R style handlers commonly used in older code
    fn check_complex_handler(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for function definitions that look like signal handlers
        if node.kind() != "function_definition" {
            return;
        }

        // Only check K&R style functions (old-style signal handlers like lostconn, myoob from FTP)
        // Modern handlers with proper signatures are better handled by the signal registration check
        if let Some(declarator) = node.child_by_field_name("declarator") {
            let decl_text = get_node_text(&declarator, source);
            // Sanitized so a comment/string literal in the function can't
            // spoof a K&R-style-parameter or unsafe-call pattern below.
            let func_text = get_sanitized_node_text(node, source);

            // Check for K&R style function definition with single parameter named signo/sig/signal
            // These are commonly used in older signal handling code
            let is_kr_style_handler = (func_text.contains("(signo)")
                || func_text.contains("(sig)")
                || func_text.contains("(signal)"))
                && !func_text.contains("(int signo)")
                && !func_text.contains("(int sig)");

            // Also look for specific function names known to be problematic signal handlers
            let is_known_handler = decl_text.contains("lostconn")
                || decl_text.contains("myoob")
                || decl_text.contains("dologout");

            if is_kr_style_handler || is_known_handler {
                // Check for complex operations in the handler body
                if let Some(body) = node.child_by_field_name("body") {
                    let body_text = get_sanitized_node_text(&body, source);

                    // Check for clearly unsafe operations in signal handlers
                    let has_unsafe_ops = body_text.contains("syslog")
                        || body_text.contains("strcmp")
                        || body_text.contains("longjmp")
                        || body_text.contains("seteuid")
                        || body_text.contains("setuid")
                        || body_text.contains("logwtmp")
                        || body_text.contains("reply("); // Network reply function

                    if has_unsafe_ops {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: "Signal handler performs complex/unsafe operations. Signal handlers should only set volatile sig_atomic_t flags or call async-signal-safe functions.".to_string(),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(
                                "Signal handlers should be minimal. Only set a volatile sig_atomic_t flag and handle the signal in the main program loop. Avoid calling non-async-signal-safe functions."
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }
}

impl CertRule for Sig02C {
    fn rule_id(&self) -> &'static str {
        "SIG02-C"
    }

    fn description(&self) -> &'static str {
        "Avoid using signals to implement normal functionality"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "SIG02-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Sig02C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for various signal misuse patterns
        for n in
            query::find_descendants_of_kinds(*node, &["call_expression", "function_definition"])
        {
            match n.kind() {
                "call_expression" => {
                    self.check_kill_call(&n, source, violations);
                    self.check_signal_registration(&n, source, violations);
                    self.check_raise_call(&n, source, violations);
                }
                "function_definition" => {
                    self.check_complex_handler(&n, source, violations);
                }
                _ => {}
            }
        }
    }
}
