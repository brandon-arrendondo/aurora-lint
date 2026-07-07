//! POS38-C: Beware of race conditions when using fork and file descriptors
//!
//! This rule detects race conditions that occur when:
//! 1. A file descriptor is opened (via open(), fopen(), etc.)
//! 2. fork() is called, duplicating the file descriptor
//! 3. Both parent and child processes use the same file descriptor
//!
//! When a process forks, file descriptors are duplicated, meaning both parent
//! and child share the same file offset and status flags. Concurrent operations
//! on the shared file descriptor create race conditions.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int fd = open("file.txt", O_RDWR);
//! if (fd == -1) { /* Handle error */ }
//! read(fd, &c, 1);
//!
//! pid_t pid = fork();
//! if (pid == 0) {
//!     read(fd, &c, 1);  // Child reads - RACE CONDITION
//! } else {
//!     read(fd, &c, 1);  // Parent reads - RACE CONDITION
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! int fd = open("file.txt", O_RDWR);
//! if (fd == -1) { /* Handle error */ }
//! read(fd, &c, 1);
//!
//! pid_t pid = fork();
//! if (pid == 0) {
//!     close(fd);  // Child closes parent's fd
//!     fd = open("file.txt", O_RDWR);  // Child opens its own fd
//!     read(fd, &c, 1);
//! } else {
//!     read(fd, &c, 1);  // Parent uses original fd
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Track file descriptors from open/fopen calls
//! - Detect fork() calls
//! - Check if file descriptors are used after fork in both parent/child branches
//! - Report violations when shared file descriptor usage is detected

use crate::manifest::{RuleCategory, Severity};
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Pos38C;

impl CertRule for Pos38C {
    fn rule_id(&self) -> &'static str {
        "POS38-C"
    }

    fn cert_id(&self) -> &'static str {
        "POS38"
    }

    fn description(&self) -> &'static str {
        "Beware of race conditions when using fork and file descriptors"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Pos38C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Only check at function_definition level to avoid nested traversals
        // (translation_unit would cause redundant checks on function children)
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_scope_for_fork_pattern(&func, source, violations);
        }
    }

    fn check_scope_for_fork_pattern(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the body node to check (function body or translation unit itself)
        let scope_node = if node.kind() == "function_definition" {
            if let Some(body) = node.child_by_field_name("body") {
                body
            } else {
                return;
            }
        } else {
            *node // translation_unit - check the whole file
        };

        // Collect file descriptors opened in this scope
        let mut file_descriptors = HashSet::new();
        self.collect_file_descriptors(&scope_node, source, &mut file_descriptors);

        // Check for fork() calls and subsequent fd usage
        self.check_for_fork_with_fd_usage(&scope_node, source, &file_descriptors, violations);
    }

    fn collect_file_descriptors(
        &self,
        node: &Node,
        source: &str,
        file_descriptors: &mut HashSet<String>,
    ) {
        for n in query::find_descendants(*node, |_| true) {
            // Look for variable declarations with file opening calls
            if n.kind() == "declaration" {
                // Get the full declaration text to check for open() calls
                let decl_text = get_node_text(&n, source);
                if self.is_file_opening_call(&decl_text) {
                    // Find init_declarator children
                    let mut cursor = n.walk();
                    for child in n.children(&mut cursor) {
                        if child.kind() == "init_declarator" {
                            // Get the declarator to extract variable name
                            if let Some(declarator) = child.child_by_field_name("declarator") {
                                if let Some(var_name) =
                                    self.extract_variable_name(&declarator, source)
                                {
                                    file_descriptors.insert(var_name);
                                }
                            }
                        }
                    }
                }
            } else if n.kind() == "assignment_expression" {
                if let Some(left) = n.child_by_field_name("left") {
                    if let Some(right) = n.child_by_field_name("right") {
                        let right_text = get_node_text(&right, source);
                        if self.is_file_opening_call(&right_text) {
                            let var_name = get_node_text(&left, source).trim().to_string();
                            file_descriptors.insert(var_name);
                        }
                    }
                }
            }
        }
    }

    fn is_file_opening_call(&self, text: &str) -> bool {
        let text = text.trim();
        text.contains("open(")
            || text.contains("fopen(")
            || text.contains("fdopen(")
            || text.contains("creat(")
            || text.contains("openat(")
    }

    #[allow(dead_code)]
    fn find_declarator<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        if node.kind() == "init_declarator" {
            node.child_by_field_name("declarator")
        } else if node.kind() == "declaration" {
            // Look for init_declarator child
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "init_declarator" {
                    if let Some(declarator) = child.child_by_field_name("declarator") {
                        return Some(declarator);
                    }
                }
            }
            None
        } else {
            None
        }
    }

    fn extract_variable_name(&self, declarator: &Node, source: &str) -> Option<String> {
        // Handle different declarator types
        match declarator.kind() {
            "identifier" => Some(get_node_text(declarator, source).trim().to_string()),
            "pointer_declarator" => {
                // Look for the identifier in the pointer declarator
                let mut cursor = declarator.walk();
                for child in declarator.children(&mut cursor) {
                    if child.kind() == "identifier" {
                        return Some(get_node_text(&child, source).trim().to_string());
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn check_for_fork_with_fd_usage(
        &self,
        node: &Node,
        source: &str,
        file_descriptors: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for fork() calls
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = n.child_by_field_name("function") {
                let func_text = get_node_text(&function, source);
                if func_text.trim() == "fork" {
                    // Found a fork() call - check for fd usage in subsequent code
                    self.check_fd_usage_after_fork(&n, source, file_descriptors, violations);
                }
            }
        }
    }

    fn check_fd_usage_after_fork(
        &self,
        fork_node: &Node,
        source: &str,
        file_descriptors: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for the parent statement containing the fork call
        if let Some(parent_stmt) = self.find_parent_statement(fork_node) {
            // Find all following if statements and check them
            if let Some(parent) = parent_stmt.parent() {
                let mut found_stmt = false;
                let mut cursor = parent.walk();
                for sibling in parent.children(&mut cursor) {
                    if found_stmt && sibling.kind() == "if_statement" {
                        // Check if this if statement has both branches (consequence and alternative)
                        // Skip error-handling if statements (e.g., `if (pid == -1)`) that don't have else
                        let has_else_branch = sibling.child_by_field_name("alternative").is_some();

                        if has_else_branch {
                            // Check both branches for fd usage
                            let parent_branch_uses_fd = self.branch_uses_file_descriptor(
                                &sibling,
                                source,
                                file_descriptors,
                                true,
                            );
                            let child_branch_uses_fd = self.branch_uses_file_descriptor(
                                &sibling,
                                source,
                                file_descriptors,
                                false,
                            );

                            if parent_branch_uses_fd && child_branch_uses_fd {
                                // Both branches use a file descriptor - potential race condition
                                let start_point = fork_node.start_position();
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Medium,
                                    message: "Race condition detected: file descriptor used after fork() in both parent and child processes. File descriptors are shared after fork(), leading to nondeterministic behavior.".to_string(),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some(
                                        "Close the file descriptor in one process and reopen it, or use separate file descriptors for parent and child.".to_string()
                                    ),
                                    ..Default::default()
                                });
                                return; // Found the violation, no need to check further
                            }
                        }
                        // Continue checking other if statements (don't return early)
                    }
                    if sibling.id() == parent_stmt.id() {
                        found_stmt = true;
                    }
                }
            }
        }
    }

    fn find_parent_statement<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        // Find the statement-level parent (expression_statement or declaration)
        // that is a direct child of a compound_statement
        let mut current = *node;
        while let Some(parent) = current.parent() {
            if parent.kind() == "expression_statement" || parent.kind() == "declaration" {
                // Verify this is a direct child of compound_statement
                if let Some(grandparent) = parent.parent() {
                    if grandparent.kind() == "compound_statement" {
                        return Some(parent);
                    }
                }
            }
            current = parent;
        }
        None
    }

    #[allow(dead_code)]
    fn find_following_if_statement<'a>(&self, stmt_node: &'a Node) -> Option<Node<'a>> {
        // Look for a sibling if statement
        if let Some(parent) = stmt_node.parent() {
            let mut found_stmt = false;
            let mut cursor = parent.walk();
            for sibling in parent.children(&mut cursor) {
                if found_stmt && sibling.kind() == "if_statement" {
                    return Some(sibling);
                }
                if sibling.id() == stmt_node.id() {
                    found_stmt = true;
                }
            }
        }
        None
    }

    fn branch_uses_file_descriptor(
        &self,
        if_stmt: &Node,
        source: &str,
        file_descriptors: &HashSet<String>,
        check_else: bool,
    ) -> bool {
        let branch = if check_else {
            // Check else/alternative branch (parent process)
            if_stmt.child_by_field_name("alternative")
        } else {
            // Check consequence branch (child process - pid == 0)
            if_stmt.child_by_field_name("consequence")
        };

        if let Some(branch_node) = branch {
            self.subtree_uses_file_descriptor(&branch_node, source, file_descriptors)
        } else {
            false
        }
    }

    fn subtree_uses_file_descriptor(
        &self,
        node: &Node,
        source: &str,
        file_descriptors: &HashSet<String>,
    ) -> bool {
        // Check for close() calls first - if fd is closed, it's not being used (safe pattern)
        if self.subtree_closes_file_descriptor(node, source, file_descriptors) {
            return false;
        }

        let node_text = get_node_text(node, source);

        // Check if any of the file descriptors are mentioned in this subtree
        // in a context that uses them (not just closes them)
        for fd in file_descriptors {
            if node_text.contains(fd) {
                return true;
            }
        }

        false
    }

    fn subtree_closes_file_descriptor(
        &self,
        node: &Node,
        source: &str,
        file_descriptors: &HashSet<String>,
    ) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(function) = n.child_by_field_name("function") else {
                return false;
            };
            let func_text = get_node_text(&function, source);
            if func_text.trim() != "close" {
                return false;
            }
            // Check if the argument is one of our file descriptors
            let Some(args) = n.child_by_field_name("arguments") else {
                return false;
            };
            let args_text = get_node_text(&args, source);
            file_descriptors.iter().any(|fd| args_text.contains(fd))
        })
        .is_some()
    }
}
