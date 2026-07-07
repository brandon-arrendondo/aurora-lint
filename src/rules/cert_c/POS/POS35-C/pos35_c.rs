//! POS35-C: Avoid race conditions while checking for the existence of a symbolic link
//!
//! This rule addresses Time-Of-Check, Time-Of-Use (TOCTOU) race conditions that occur
//! when checking if a file is a symbolic link before performing file operations.
//! The vulnerability arises from the time gap between checking and using the file,
//! during which an attacker could replace a regular file with a symbolic link.
//!
//! ## Non-compliant examples:
//!
//! **Using lstat() then open() separately:**
//! ```c
//! struct stat lstat_info;
//! int fd;
//!
//! if (lstat(filename, &lstat_info) == -1) {
//!     /* Handle error */
//! }
//!
//! if (!S_ISLNK(lstat_info.st_mode)) {
//!     fd = open(filename, O_RDWR);  // TOCTOU race condition!
//!     if (fd == -1) {
//!         /* Handle error */
//!     }
//! }
//! ```
//!
//! ## Compliant solutions:
//!
//! **POSIX.1-2008 or newer - Use O_NOFOLLOW:**
//! ```c
//! int fd = open(filename, O_RDWR|O_NOFOLLOW);
//! if (fd == -1) {
//!     /* Handle error */
//! }
//! ```
//!
//! **POSIX.1-2001 or older - Compare attributes:**
//! ```c
//! struct stat lstat_info;
//! struct stat fstat_info;
//! int fd;
//!
//! if (lstat(filename, &lstat_info) == -1) {
//!     /* handle error */
//! }
//!
//! fd = open(filename, O_RDWR);
//! if (fd == -1) {
//!     /* handle error */
//! }
//!
//! if (fstat(fd, &fstat_info) == -1) {
//!     /* handle error */
//! }
//!
//! if (lstat_info.st_mode == fstat_info.st_mode &&
//!     lstat_info.st_ino == fstat_info.st_ino &&
//!     lstat_info.st_dev == fstat_info.st_dev) {
//!     // Safe to use file
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pos35C;

impl Pos35C {
    pub fn new() -> Self {
        Self
    }

    /// Check if a call expression is lstat()
    fn is_lstat_call(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source).trim();
                return func_name == "lstat";
            }
        }
        false
    }

    /// Check if a call expression is open() without O_NOFOLLOW
    fn is_open_without_nofollow(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source).trim();
                if func_name == "open" {
                    // Check if O_NOFOLLOW flag is present in arguments
                    if let Some(arguments) = node.child_by_field_name("arguments") {
                        let args_text = get_node_text(&arguments, source);
                        return !args_text.contains("O_NOFOLLOW");
                    }
                    return true; // open() without any check
                }
            }
        }
        false
    }

    /// Check if code contains S_ISLNK() macro usage
    fn contains_s_islnk(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(function) = n.child_by_field_name("function") else {
                return false;
            };
            get_node_text(&function, source).trim() == "S_ISLNK"
        })
        .is_some()
    }

    /// Check for lstat() followed by S_ISLNK() check and then open()
    fn check_lstat_open_pattern(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for lstat() calls
        if self.is_lstat_call(node, source) {
            // Check if this is in a function scope with subsequent open() calls
            if let Some(parent) = node.parent() {
                if let Some(scope) = self.find_containing_scope(&parent) {
                    // Check if there's an S_ISLNK check and open() call in the same scope
                    if self.contains_s_islnk(&scope, source) {
                        if self.contains_open_without_nofollow(&scope, source) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                message: "Potential TOCTOU race condition: lstat() check for symbolic link followed by separate open() call. The file could be replaced with a symbolic link between the check and use.".to_string(),
                                file_path: String::new(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                suggestion: Some(
                                    "Use open() with O_NOFOLLOW flag (POSIX.1-2008+), or use lstat() + open() + fstat() pattern with attribute comparison (POSIX.1-2001)".to_string()
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    /// Find containing scope (compound_statement or translation_unit)
    fn find_containing_scope<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = *node;
        while let Some(parent) = current.parent() {
            // Check for compound_statement (function body) or translation_unit (file scope)
            if parent.kind() == "compound_statement" || parent.kind() == "translation_unit" {
                return Some(parent);
            }
            current = parent;
        }
        None
    }

    /// Check if compound statement contains open() without O_NOFOLLOW
    fn contains_open_without_nofollow(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| self.is_open_without_nofollow(&n, source)).is_some()
    }
}

impl CertRule for Pos35C {
    fn rule_id(&self) -> &'static str {
        "POS35-C"
    }

    fn description(&self) -> &'static str {
        "Avoid race conditions while checking for the existence of a symbolic link"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "POS35-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Pos35C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_lstat_open_pattern(&call, source, violations);
        }
    }
}
