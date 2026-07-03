//! FIO18-C: Never expect fwrite() to terminate the writing process at a null character
//!
//! fwrite() writes exactly the number of bytes specified, regardless of null characters.
//! Using a size that doesn't match the actual string length may write uninitialized data
//! or truncate the content incorrectly.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! fwrite(buffer, 1, size2, filedes);  // size2 not derived from strlen(buffer)
//! ```
//!
//! **Compliant:**
//! ```c
//! size2 = strlen(buffer) + 1;
//! fwrite(buffer, 1, size2, filedes);  // size2 properly set from strlen
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Fio18C;

impl CertRule for Fio18C {
    fn rule_id(&self) -> &'static str {
        "FIO18-C"
    }

    fn description(&self) -> &'static str {
        "Never expect fwrite() to terminate the writing process at a null character"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "FIO18-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: collect variables that have been assigned from strlen()
        let mut strlen_vars: HashSet<String> = HashSet::new();
        self.collect_strlen_assignments(node, source, &mut strlen_vars);

        // Second pass: check fwrite() calls
        self.check_fwrite_usage(node, source, &strlen_vars, &mut violations);

        violations
    }
}

impl Fio18C {
    /// Collect variables that have been assigned from strlen() expressions
    fn collect_strlen_assignments(
        &self,
        node: &Node,
        source: &str,
        strlen_vars: &mut HashSet<String>,
    ) {
        // Check for assignment expressions like: size2 = strlen(buffer) + 1;
        for n in
            query::find_descendants_of_kinds(*node, &["assignment_expression", "init_declarator"])
        {
            let node_text = get_node_text(&n, source);

            // Check if right side contains strlen
            if node_text.contains("strlen") {
                // Extract the variable name from left side
                if let Some(left) = n.child_by_field_name("left") {
                    let var_name = get_node_text(&left, source).trim().to_string();
                    strlen_vars.insert(var_name);
                } else if let Some(declarator) = n.child_by_field_name("declarator") {
                    // For init_declarator, get the name
                    let var_name = self.extract_identifier(&declarator, source);
                    if !var_name.is_empty() {
                        strlen_vars.insert(var_name);
                    }
                }
            }
        }
    }

    /// Extract identifier name from a declarator node
    fn extract_identifier(&self, node: &Node, source: &str) -> String {
        if node.kind() == "identifier" {
            return get_node_text(node, source).trim().to_string();
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let result = self.extract_identifier(&child, source);
                if !result.is_empty() {
                    return result;
                }
            }
        }

        String::new()
    }

    /// Check for potentially problematic fwrite() usage
    fn check_fwrite_usage(
        &self,
        node: &Node,
        source: &str,
        strlen_vars: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                if func_name == "fwrite" {
                    if let Some(args) = call.child_by_field_name("arguments") {
                        self.analyze_fwrite_args(&args, source, &call, strlen_vars, violations);
                    }
                }
            }
        }
    }

    /// Analyze fwrite arguments for potential issues
    /// fwrite(ptr, size, nmemb, stream)
    fn analyze_fwrite_args(
        &self,
        args: &Node,
        source: &str,
        call_node: &Node,
        strlen_vars: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let arg_list = self.extract_args(args, source);

        if arg_list.len() >= 3 {
            let buffer_arg = &arg_list[0];
            let nmemb = &arg_list[2];

            // Check if nmemb uses strlen() directly
            if nmemb.contains("strlen") {
                // This is compliant
                return;
            }

            // Check if nmemb is a variable that was assigned from strlen()
            let nmemb_trimmed = nmemb.trim();
            if strlen_vars.contains(nmemb_trimmed) {
                // This is compliant - the variable was assigned from strlen()
                return;
            }

            // Check for sizeof() which is suspicious for string data
            if nmemb.contains("sizeof") {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    message: format!(
                        "fwrite() using sizeof() for count argument when writing '{}'. \
                         May write uninitialized data beyond null terminator.",
                        buffer_arg
                    ),
                    severity: self.severity(),
                    line: call_node.start_position().row + 1,
                    column: call_node.start_position().column + 1,
                    file_path: String::new(),
                    suggestion: Some(
                        "For strings, use strlen(buffer)+1 to write only the string content. \
                         sizeof() writes the entire buffer regardless of string length."
                            .to_string(),
                    ),
                    requires_manual_review: Some(true),
                });
                return;
            }

            // If nmemb is a variable that wasn't derived from strlen(), flag it
            // This catches cases like: fwrite(buffer, 1, size2, fp) where size2 != strlen(buffer)+1
            if !nmemb.chars().all(|c| c.is_ascii_digit()) {
                // It's a variable, not a literal number
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    message: format!(
                        "fwrite() count argument '{}' not derived from strlen({}). \
                         May write incorrect number of bytes.",
                        nmemb, buffer_arg
                    ),
                    severity: self.severity(),
                    line: call_node.start_position().row + 1,
                    column: call_node.start_position().column + 1,
                    file_path: String::new(),
                    suggestion: Some(format!(
                        "For null-terminated strings, use strlen({}) + 1 to include \
                         the null terminator but avoid writing uninitialized data.",
                        buffer_arg
                    )),
                    requires_manual_review: Some(true),
                });
            }
        }
    }

    /// Extract arguments from argument list
    fn extract_args(&self, args: &Node, source: &str) -> Vec<String> {
        let mut result = Vec::new();
        for i in 0..args.child_count() {
            if let Some(child) = args.child(i) {
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    result.push(get_node_text(&child, source).trim().to_string());
                }
            }
        }
        result
    }
}
