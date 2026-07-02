use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;

pub struct Fio21C;

impl CertRule for Fio21C {
    fn rule_id(&self) -> &'static str {
        "FIO21-C"
    }

    fn description(&self) -> &'static str {
        "Do not create temporary files in shared directories"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "FIO21-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Fio21C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for calls to insecure temporary file functions
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            let node = &n;
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                match func_name.trim() {
                    "tmpfile" => {
                        // tmpfile() creates files in shared /tmp directory
                        let position = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            line: position.row + 1,
                            column: position.column + 1,
                            file_path: String::new(),
                            message: "tmpfile() creates temporary files in a shared directory (typically /tmp), which is vulnerable to race conditions and symlink attacks. Use mkstemp() in a secure directory instead.".to_string(),
                            suggestion: Some("Use mkstemp() with a template in a secure, user-specific directory".to_string()),
                            requires_manual_review: None,
                        });
                    }
                    "tmpnam" | "tempnam" => {
                        // tmpnam/tempnam are vulnerable to TOCTOU races
                        let position = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            line: position.row + 1,
                            column: position.column + 1,
                            file_path: String::new(),
                            message: format!("{}() generates a file name but does not create the file, leading to TOCTOU (time-of-check-time-of-use) race conditions. Use mkstemp() instead.", func_name),
                            suggestion: Some("Use mkstemp() which atomically creates the file with exclusive permissions".to_string()),
                            requires_manual_review: None,
                        });
                    }
                    "mktemp" => {
                        // mktemp is deprecated and insecure
                        let position = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            line: position.row + 1,
                            column: position.column + 1,
                            file_path: String::new(),
                            message: "mktemp() is deprecated and insecure. It creates a predictable file name without actually creating the file, leading to TOCTOU race conditions. Use mkstemp() instead.".to_string(),
                            suggestion: Some("Use mkstemp() which atomically creates the file with secure permissions".to_string()),
                            requires_manual_review: None,
                        });
                    }
                    "fopen" | "open" => {
                        // Check if opening a file with parameters that might be in /tmp
                        // or with temp-related variable names
                        if let Some(arguments) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = arguments.named_child(0) {
                                let arg_text = get_node_text(&first_arg, source);

                                // Check for common temp directory patterns or temp file naming
                                if arg_text.contains("/tmp/") 
                                    || arg_text.contains("/var/tmp/")
                                    || arg_text.contains("P_tmpdir")
                                    || arg_text.contains("tmpnam")
                                    || arg_text.contains("tempnam")
                                    || (arg_text.contains("file_name") && !arg_text.contains("\"")) // variable named file_name (not string literal)
                                    || self.is_in_function_with_tmpnam(node, source)
                                {
                                    let position = node.start_position();
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: self.severity(),
                                        line: position.row + 1,
                                        column: position.column + 1,
                                        file_path: String::new(),
                                        message: format!("{}() called with a file path that may be in a shared directory or created insecurely. Creating files in shared directories like /tmp is vulnerable to race conditions and symlink attacks.", func_name),
                                        suggestion: Some("Create temporary files in a secure, user-specific directory using mkstemp()".to_string()),
                                        requires_manual_review: None,
                                    });
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Check if we're in a function that uses tmpnam/tempnam
    fn is_in_function_with_tmpnam(&self, node: &Node, source: &str) -> bool {
        // Walk up to find the containing function
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "function_definition" {
                // Check if this function contains tmpnam/tempnam calls
                return self.contains_tmpnam_call(&parent, source);
            }
            current = parent.parent();
        }
        false
    }

    fn contains_tmpnam_call(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(function) = n.child_by_field_name("function") else {
                return false;
            };
            let func_name = get_node_text(&function, source);
            func_name == "tmpnam" || func_name == "tempnam"
        })
        .is_some()
    }
}
