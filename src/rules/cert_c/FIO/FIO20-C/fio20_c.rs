//! FIO20-C: Avoid unintentional truncation when using fgets() or fgetws()
//!
//! fgets() reads at most n-1 characters. If input is longer, it's truncated
//! without warning. Code should check for newline to detect truncation.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! char buf[10];
//! fgets(buf, sizeof(buf), stdin);  // No truncation check
//! process(buf);
//! ```
//!
//! **Compliant:**
//! ```c
//! char buf[10];
//! fgets(buf, sizeof(buf), stdin);
//! if (strchr(buf, '\n') == NULL) {
//!     // Handle truncation
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Fio20C;

impl CertRule for Fio20C {
    fn rule_id(&self) -> &'static str {
        "FIO20-C"
    }

    fn description(&self) -> &'static str {
        "Avoid unintentional truncation when using fgets() or fgetws()"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "FIO20-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_fgets_truncation(node, source, &mut violations);
        violations
    }
}

impl Fio20C {
    /// Check for fgets/fgetws without truncation handling
    fn check_fgets_truncation(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                if func_name == "fgets" || func_name == "fgetws" {
                    // Check if followed by newline check
                    if !self.has_newline_check(&call, source) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: format!(
                                "{}() without truncation check. Input may be silently truncated.",
                                func_name
                            ),
                            severity: self.severity(),
                            line: call.start_position().row + 1,
                            column: call.start_position().column + 1,
                            file_path: String::new(),
                            suggestion: Some(
                                "Check for newline character to detect truncation: \
                                 if (strchr(buf, '\\n') == NULL) { /* handle truncation */ }"
                                    .to_string(),
                            ),
                            requires_manual_review: Some(true),
                        });
                    }

                    // Check for small buffer sizes
                    if let Some(size) = self.get_buffer_size(&call, source) {
                        if size < 32 {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                message: format!(
                                    "{}() with small buffer size ({}). High risk of truncation.",
                                    func_name, size
                                ),
                                severity: self.severity(),
                                line: call.start_position().row + 1,
                                column: call.start_position().column + 1,
                                file_path: String::new(),
                                suggestion: Some(
                                    "Consider larger buffer for user input, or validate input length"
                                        .to_string(),
                                ),
                                requires_manual_review: None,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Check if there's a newline check after fgets
    fn has_newline_check(&self, node: &Node, source: &str) -> bool {
        // Look for strchr or memchr with '\n' in nearby code
        if let Some(parent) = node.parent() {
            if let Some(grandparent) = parent.parent() {
                let code_block = get_node_text(&grandparent, source);
                // Simple heuristic: check if there's a newline check nearby
                if code_block.contains("strchr") && code_block.contains("'\\n'") {
                    return true;
                }
                if code_block.contains("memchr") && code_block.contains("'\\n'") {
                    return true;
                }
                // Also check for direct newline comparison
                if code_block.contains("[") && code_block.contains("'\\n'") {
                    return true;
                }
            }
        }
        false
    }

    /// Get buffer size from fgets call if it's a literal
    fn get_buffer_size(&self, node: &Node, source: &str) -> Option<usize> {
        if let Some(args) = node.child_by_field_name("arguments") {
            let mut arg_count = 0;
            for i in 0..args.child_count() {
                if let Some(child) = args.child(i) {
                    if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                        arg_count += 1;
                        if arg_count == 2 {
                            // Second argument is size
                            let size_text = get_node_text(&child, source).trim();
                            if let Ok(size) = size_text.parse::<usize>() {
                                return Some(size);
                            }
                        }
                    }
                }
            }
        }
        None
    }
}
