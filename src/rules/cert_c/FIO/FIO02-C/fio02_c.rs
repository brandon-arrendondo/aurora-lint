//! FIO02-C: Canonicalize path names originating from tainted sources
//!
//! This rule detects file operations on path names from untrusted sources without
//! proper canonicalization. Path names should be converted to canonical form using
//! realpath() or canonicalize_file_name() before validation or file operations.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int main(int argc, char *argv[]) {
//!   if (fopen(argv[1], "w") == NULL) {  // Direct use of argv without canonicalization
//!     return 1;
//!   }
//! }
//! ```
//!
//! **Non-compliant:**
//! ```c
//! char *env_path = getenv("CONFIG_FILE");
//! FILE *f = fopen(env_path, "r");  // Direct use of environment variable
//! ```
//!
//! **Compliant:**
//! ```c
//! int main(int argc, char *argv[]) {
//!   char *canonical = realpath(argv[1], NULL);
//!   if (canonical == NULL) {
//!     return 1;
//!   }
//!   if (fopen(canonical, "w") == NULL) {
//!     free(canonical);
//!     return 1;
//!   }
//!   free(canonical);
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Track tainted data sources (argv, getenv, user input functions)
//! - Track canonicalization calls (realpath, canonicalize_file_name)
//! - Detect file operations (fopen, open, etc.) on tainted paths
//! - Flag violations when file operations use tainted paths without canonicalization

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Fio02C;

impl CertRule for Fio02C {
    fn rule_id(&self) -> &'static str {
        "FIO02-C"
    }

    fn description(&self) -> &'static str {
        "Canonicalize path names originating from tainted sources"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "FIO02-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Collect tainted variables in this scope
        let mut tainted_vars = HashSet::new();
        let mut canonicalized_vars = HashSet::new();

        self.check_node(
            node,
            source,
            &mut violations,
            &mut tainted_vars,
            &mut canonicalized_vars,
        );

        violations
    }
}

impl Fio02C {
    fn check_node(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        tainted_vars: &mut HashSet<String>,
        canonicalized_vars: &mut HashSet<String>,
    ) {
        for n in query::find_descendants(*node, |n| {
            matches!(
                n.kind(),
                "function_definition"
                    | "assignment_expression"
                    | "init_declarator"
                    | "call_expression"
            )
        }) {
            match n.kind() {
                "function_definition" => {
                    // Check for main function with argv parameter
                    if let Some(declarator) = n.child_by_field_name("declarator") {
                        if self.is_main_function(&declarator, source) {
                            // Mark argv as tainted
                            tainted_vars.insert("argv".to_string());
                        }
                    }
                }
                "assignment_expression" | "init_declarator" => {
                    self.check_assignment(&n, source, tainted_vars, canonicalized_vars);
                }
                "call_expression" => {
                    self.check_call_expression(
                        &n,
                        source,
                        violations,
                        tainted_vars,
                        canonicalized_vars,
                    );
                }
                _ => {}
            }
        }
    }

    fn is_main_function(&self, declarator: &Node, source: &str) -> bool {
        // Check if this is the main function
        if let Some(function_declarator) = self.find_function_declarator(*declarator) {
            if let Some(name_node) = function_declarator.child_by_field_name("declarator") {
                let func_name = get_node_text(&name_node, source).trim();
                if func_name == "main" {
                    return true;
                }
            }
        }
        false
    }

    fn find_function_declarator<'a>(&self, node: Node<'a>) -> Option<Node<'a>> {
        if node.kind() == "function_declarator" {
            return Some(node);
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(result) = self.find_function_declarator(child) {
                    return Some(result);
                }
            }
        }
        None
    }

    fn check_assignment(
        &self,
        node: &Node,
        source: &str,
        tainted_vars: &mut HashSet<String>,
        canonicalized_vars: &mut HashSet<String>,
    ) {
        // Get the variable being assigned
        let var_name = if node.kind() == "assignment_expression" {
            if let Some(left) = node.child_by_field_name("left") {
                get_node_text(&left, source).trim().to_string()
            } else {
                return;
            }
        } else if node.kind() == "init_declarator" {
            if let Some(declarator) = node.child_by_field_name("declarator") {
                self.extract_identifier(&declarator, source)
                    .unwrap_or_default()
            } else {
                return;
            }
        } else {
            return;
        };

        // Get the value being assigned
        let value_node = if node.kind() == "assignment_expression" {
            node.child_by_field_name("right")
        } else {
            node.child_by_field_name("value")
        };

        if let Some(value) = value_node {
            let _value_text = get_node_text(&value, source).trim();

            // Check if assigned from tainted source
            if self.is_tainted_source(&value, source, tainted_vars) {
                tainted_vars.insert(var_name.clone());
            }

            // Check if assigned from canonicalization function
            if self.is_canonicalization_call(&value, source) {
                canonicalized_vars.insert(var_name.clone());
                // Canonicalized variable is no longer tainted
                tainted_vars.remove(&var_name);
            }
        }
    }

    fn extract_identifier(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).trim().to_string());
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(id) = self.extract_identifier(&child, source) {
                    return Some(id);
                }
            }
        }
        None
    }

    fn is_tainted_source(&self, node: &Node, source: &str, tainted_vars: &HashSet<String>) -> bool {
        query::find_first_descendant(*node, |n| {
            match n.kind() {
                "call_expression" => {
                    // Check for taint source functions
                    if let Some(func) = n.child_by_field_name("function") {
                        let func_name = get_node_text(&func, source).trim();
                        if self.is_taint_source_function(func_name) {
                            return true;
                        }
                    }
                }
                "subscript_expression" => {
                    // Check for argv[i] access
                    if let Some(array) = n.child_by_field_name("argument") {
                        let array_name = get_node_text(&array, source).trim();
                        if tainted_vars.contains(array_name) || array_name == "argv" {
                            return true;
                        }
                    }
                }
                "identifier" => {
                    let var_name = get_node_text(&n, source).trim();
                    if tainted_vars.contains(var_name) {
                        return true;
                    }
                }
                _ => {}
            }
            false
        })
        .is_some()
    }

    fn is_taint_source_function(&self, func_name: &str) -> bool {
        matches!(
            func_name,
            "getenv"
                | "gets"
                | "fgets"
                | "scanf"
                | "fscanf"
                | "sscanf"
                | "getchar"
                | "fgetc"
                | "getc"
                | "read"
                | "recv"
                | "recvfrom"
                | "recvmsg"
        )
    }

    fn is_canonicalization_call(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = get_node_text(&func, source).trim();
                return matches!(func_name, "realpath" | "canonicalize_file_name");
            }
        }
        false
    }

    fn check_call_expression(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        tainted_vars: &HashSet<String>,
        canonicalized_vars: &HashSet<String>,
    ) {
        if let Some(func) = node.child_by_field_name("function") {
            let func_name = get_node_text(&func, source).trim();

            if self.is_file_operation_function(func_name) {
                // Get the first argument (path name)
                if let Some(args) = node.child_by_field_name("arguments") {
                    if let Some(first_arg) = self.get_first_argument(&args) {
                        let arg_text = get_node_text(&first_arg, source).trim();

                        // Check if the argument is tainted
                        if self.is_tainted_source(&first_arg, source, tainted_vars) {
                            // Check if it was canonicalized
                            if !self.is_canonicalized_var(arg_text, canonicalized_vars) {
                                self.report_violation(
                                    node, source, func_name, arg_text, violations,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    fn is_file_operation_function(&self, func_name: &str) -> bool {
        matches!(
            func_name,
            "fopen"
                | "open"
                | "freopen"
                | "creat"
                | "stat"
                | "lstat"
                | "access"
                | "chmod"
                | "chown"
                | "remove"
                | "unlink"
                | "rename"
                | "mkdir"
                | "rmdir"
                | "pathconf"
                | "fpathconf"
                | "readlink"
                | "symlink"
                | "link"
                | "chdir"
                | "opendir"
                | "execve"
                | "execv"
                | "execl"
                | "execlp"
                | "execvp"
                | "CreateFile"
                | "CreateFileA"
                | "CreateFileW"
                | "DeleteFile"
                | "DeleteFileA"
                | "DeleteFileW"
                | "MoveFile"
                | "MoveFileA"
                | "MoveFileW"
                | "CopyFile"
                | "CopyFileA"
                | "CopyFileW"
                | "_wfopen"
                | "_wopen"
                | "GetFullPathName"
                | "GetFullPathNameA"
                | "GetFullPathNameW"
        )
    }

    fn get_first_argument<'a>(&self, args_node: &'a Node<'a>) -> Option<Node<'a>> {
        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    return Some(child);
                }
            }
        }
        None
    }

    fn is_canonicalized_var(&self, arg_text: &str, canonicalized_vars: &HashSet<String>) -> bool {
        // Simple check - just look for variable name
        canonicalized_vars.iter().any(|var| arg_text.contains(var))
    }

    fn report_violation(
        &self,
        node: &Node,
        source: &str,
        func_name: &str,
        arg_text: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let start_point = node.start_position();
        let _call_text = get_node_text(node, source).trim().to_string();

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "File operation '{}' uses tainted path '{}' without canonicalization. Use realpath() or canonicalize_file_name() before file operations.",
                func_name,
                if arg_text.len() > 40 {
                    format!("{}...", &arg_text[..40])
                } else {
                    arg_text.to_string()
                }
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(format!(
                "Canonicalize the path before use:\n  char *canonical = realpath({}, NULL);\n  if (canonical == NULL) {{ /* handle error */ }}\n  {}(canonical, ...);\n  free(canonical);",
                arg_text,
                func_name
            )),
            ..Default::default()
        });
    }
}
