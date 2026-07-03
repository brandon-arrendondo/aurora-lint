//! WIN05-C: Do not violate least privilege when creating processes or accessing registry
//!
//! Detects two patterns:
//! 1. CreateProcess with unquoted paths containing spaces (path interception)
//! 2. Registry operations using HKEY_LOCAL_MACHINE (excessive privilege)

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

/// Functions that take a command line string that should have quoted paths.
/// (function_name, argument_index of lpCommandLine, 0-based)
const CREATE_PROCESS_FUNCTIONS: &[(&str, usize)] = &[
    ("CreateProcessA", 1),
    ("CreateProcessW", 1),
    ("CreateProcessAsUserA", 2),
    ("CreateProcessAsUserW", 2),
];

/// Registry functions whose first argument is a root key handle.
const REGISTRY_FUNCTIONS: &[&str] = &[
    "RegCreateKeyA",
    "RegCreateKeyW",
    "RegCreateKeyExA",
    "RegCreateKeyExW",
    "RegOpenKeyExA",
    "RegOpenKeyExW",
];

/// SHRegCreate functions that use SHREGSET_HKLM flag (arg index 4).
const SHREG_CREATE_FUNCTIONS: &[&str] = &["SHRegCreateUSKeyA", "SHRegCreateUSKeyW"];

/// SHRegOpen functions where fIgnoreHKCU=TRUE (arg index 4) means HKLM.
const SHREG_OPEN_FUNCTIONS: &[&str] = &["SHRegOpenUSKeyA", "SHRegOpenUSKeyW"];

pub struct Win05C;

impl Win05C {
    pub fn new() -> Self {
        Self
    }

    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_call(&call, source, violations);
        }
    }

    fn check_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let func_name = match node.child_by_field_name("function") {
            Some(f) => get_node_text(&f, source).to_string(),
            None => return,
        };

        let args = match node.child_by_field_name("arguments") {
            Some(a) => a,
            None => return,
        };

        // Check CreateProcess for unquoted paths
        for &(cp_func, arg_idx) in CREATE_PROCESS_FUNCTIONS {
            if func_name == cp_func {
                if let Some(arg) = self.get_nth_argument(&args, arg_idx) {
                    self.check_unquoted_path(&arg, source, &func_name, violations);
                }
                return;
            }
        }

        // Check registry functions for HKEY_LOCAL_MACHINE
        if REGISTRY_FUNCTIONS.contains(&func_name.as_str()) {
            if let Some(first_arg) = self.get_nth_argument(&args, 0) {
                let arg_text = get_node_text(&first_arg, source).trim().to_string();
                if arg_text == "HKEY_LOCAL_MACHINE" || arg_text == "HKEY_CLASSES_ROOT" {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: format!(
                            "Registry operation '{}' uses '{}' which requires administrator \
                             privileges. Use HKEY_CURRENT_USER to follow least privilege.",
                            func_name, arg_text
                        ),
                        file_path: String::new(),
                        line: first_arg.start_position().row + 1,
                        column: first_arg.start_position().column + 1,
                        suggestion: Some(
                            "Use HKEY_CURRENT_USER instead of HKEY_LOCAL_MACHINE".to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }

        // Check SHRegCreate functions for SHREGSET_HKLM flag (5th argument, index 4)
        if SHREG_CREATE_FUNCTIONS.contains(&func_name.as_str()) {
            if let Some(flag_arg) = self.get_nth_argument(&args, 4) {
                let flag_text = get_node_text(&flag_arg, source).trim().to_string();
                if flag_text == "SHREGSET_HKLM" || flag_text.contains("SHREGSET_HKLM") {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: format!(
                            "Registry operation '{}' uses SHREGSET_HKLM which targets \
                             HKEY_LOCAL_MACHINE. Use SHREGSET_HKCU to follow least privilege.",
                            func_name
                        ),
                        file_path: String::new(),
                        line: flag_arg.start_position().row + 1,
                        column: flag_arg.start_position().column + 1,
                        suggestion: Some("Use SHREGSET_HKCU instead of SHREGSET_HKLM".to_string()),
                        ..Default::default()
                    });
                }
            }
        }

        // Check SHRegOpen functions for fIgnoreHKCU=TRUE (5th argument, index 4)
        if SHREG_OPEN_FUNCTIONS.contains(&func_name.as_str()) {
            if let Some(flag_arg) = self.get_nth_argument(&args, 4) {
                let flag_text = get_node_text(&flag_arg, source).trim().to_string();
                if flag_text == "TRUE" || flag_text == "true" || flag_text == "1" {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: format!(
                            "Registry operation '{}' with fIgnoreHKCU=TRUE targets \
                             HKEY_LOCAL_MACHINE. Set to FALSE to follow least privilege.",
                            func_name
                        ),
                        file_path: String::new(),
                        line: flag_arg.start_position().row + 1,
                        column: flag_arg.start_position().column + 1,
                        suggestion: Some(
                            "Set fIgnoreHKCU to FALSE to use HKEY_CURRENT_USER".to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check if a CreateProcess command line argument has an unquoted path with spaces.
    fn check_unquoted_path(
        &self,
        arg: &Node,
        source: &str,
        func_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Only check string literals
        if arg.kind() != "string_literal" {
            return;
        }

        let text = get_node_text(arg, source);
        let content = text.trim_matches('"');

        // Skip NULL or empty
        if content.is_empty() || text == "NULL" || text == "0" {
            return;
        }

        // Check if path contains a space
        if !content.contains(' ') {
            return;
        }

        // Check if the path is properly quoted with escaped quotes
        // Good: "\"C:\\Program Files\\App\" arg1 arg2"
        // Bad:  "C:\\Program Files\\App arg1 arg2"
        if content.starts_with("\\\"") || content.starts_with("\"") {
            return; // Properly quoted
        }

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message: format!(
                "Unquoted path with spaces in '{}' command line. \
                 This allows path interception attacks.",
                func_name
            ),
            file_path: String::new(),
            line: arg.start_position().row + 1,
            column: arg.start_position().column + 1,
            suggestion: Some(
                "Quote the executable path: \\\"C:\\\\Program Files\\\\App\\\" arg1 arg2"
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    fn get_nth_argument<'a>(&self, args: &Node<'a>, index: usize) -> Option<Node<'a>> {
        let mut count = 0;
        for i in 0..args.child_count() {
            if let Some(child) = args.child(i) {
                let kind = child.kind();
                if kind != "(" && kind != ")" && kind != "," {
                    if count == index {
                        return Some(child);
                    }
                    count += 1;
                }
            }
        }
        None
    }
}

impl CertRule for Win05C {
    fn rule_id(&self) -> &'static str {
        "WIN05-C"
    }

    fn description(&self) -> &'static str {
        "Do not violate least privilege when creating processes or accessing registry"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "WIN05-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}
