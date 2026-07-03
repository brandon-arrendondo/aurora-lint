//! POS30-C: Use the readlink() function properly
//!
//! The readlink() function does NOT null-terminate its buffer. It returns the number
//! of bytes written. Writing buf[len] = '\0' when len equals sizeof(buf) causes a
//! buffer overflow (writes 1 byte past the end).
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! char buf[1024];
//! ssize_t len = readlink("/usr/bin/perl", buf, sizeof(buf));
//! buf[len] = '\0';  // VIOLATION: if len == 1024, writes past end
//! ```
//!
//! **Compliant:**
//! ```c
//! char buf[1024];
//! ssize_t len = readlink("/usr/bin/perl", buf, sizeof(buf) - 1);
//! if (len != -1) {
//!     buf[len] = '\0';  // OK: len < 1024
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find readlink() calls
//! - Check if size argument is sizeof(buf) without -1
//! - Check if result is used to index buffer without error check

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pos30C;

impl CertRule for Pos30C {
    fn rule_id(&self) -> &'static str {
        "POS30-C"
    }

    fn description(&self) -> &'static str {
        "Use the readlink() function properly"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "POS30-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        // Look for readlink() calls
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                if func_name == "readlink" {
                    self.check_readlink_call(&call, source, &mut violations);
                }
            }
        }
        violations
    }
}

impl Pos30C {
    fn check_readlink_call(&self, call: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Get arguments: readlink(path, buf, size)
        let args = match call.child_by_field_name("arguments") {
            Some(a) => a,
            None => return,
        };

        // Get all children, skipping commas and parentheses
        let mut arg_nodes = Vec::new();
        for i in 0..args.child_count() {
            if let Some(child) = args.child(i) {
                let kind = child.kind();
                // Skip structural tokens
                if kind != "," && kind != "(" && kind != ")" {
                    arg_nodes.push(child);
                }
            }
        }

        if arg_nodes.len() < 3 {
            return;
        }

        // Third argument is size - get full text including expressions like sizeof(buf)-1
        let size_arg = &arg_nodes[2];
        let size_text = get_node_text(size_arg, source);

        // Check if it's sizeof(buf) or bufsize without -1
        // Violations:
        // 1. sizeof(buf) without - 1
        // 2. Plain variable (bufsize) - assumes full size used
        let is_violation = (size_text.contains("sizeof") && !size_text.contains("-"))
            || (!size_text.contains("sizeof")
                && !size_text.contains("-")
                && !size_text.chars().all(|c| c.is_ascii_digit()));

        if is_violation {
            // VIOLATION: using full buffer size without subtracting 1
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "readlink() called with size '{}' without reserving space for null terminator - may cause buffer overflow",
                    size_text.trim()
                ),
                file_path: String::new(),
                line: call.start_position().row + 1,
                column: call.start_position().column + 1,
                suggestion: Some(
                    "Subtract 1 from buffer size (e.g., sizeof(buf) - 1 or bufsize - 1) and check return value != -1 before using".to_string()
                ),
                ..Default::default()
            });
        }
    }
}
