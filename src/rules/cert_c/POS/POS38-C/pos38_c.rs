// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

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
//! - Track descriptors a call resolving to open/openat/creat/fopen/fdopen
//!   initializes or assigns ([`thread_api::library_call`]: `popen` is not
//!   `open`, nor is a project's own `open`), keyed by the declaration the
//!   name resolves to, or by the whole field path (`s->fd`) when it has none
//! - Detect fork() calls
//! - Check if file descriptors are used after fork in both parent/child
//!   branches: an identifier in a branch counts only when it resolves to the
//!   descriptor's declaration (ADR-0006), so a shadowing local or the same
//!   letters inside a string literal is not a use; `close()` likewise
//! - Report violations when shared file descriptor usage is detected

use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::utility::cert_c::ast_utils::{get_node_text, resolve_identifier_declarator};
use crate::utility::cert_c::thread_api::{self, ProjectFunctions};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashSet;
use tree_sitter::Node;

/// The library functions whose result is a fresh file descriptor or stream.
const OPEN_FUNCTIONS: &[&str] = &["open", "openat", "creat", "fopen", "fdopen"];

/// One descriptor the function opens.
#[derive(Clone, PartialEq, Eq, Hash)]
enum Descriptor {
    /// A name and the start of the declaration it resolves to, `None` when
    /// nothing in reach declares it.
    Named(String, Option<usize>),
    /// A field path with no declarator of its own (`s->fd`, `ctx.fp`),
    /// compared as a whole token sequence.
    Path(String),
}

/// `expr` with any enclosing parentheses and casts removed.
fn strip_parens_and_casts<'a>(expr: Node<'a>) -> Node<'a> {
    let mut expr = expr;
    loop {
        let inner = match expr.kind() {
            "parenthesized_expression" => expr.named_child(0),
            "cast_expression" => expr.child_by_field_name("value"),
            _ => None,
        };
        match inner {
            Some(inner) => expr = inner,
            None => return expr,
        }
    }
}

/// `node`'s text with whitespace removed, so `s -> fd` and `s->fd` agree.
fn token_text(node: &Node, source: &str) -> String {
    get_node_text(node, source)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

#[derive(Default)]
pub struct Pos38C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

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

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
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
        let mut file_descriptors: HashSet<Descriptor> = HashSet::new();
        self.collect_file_descriptors(&scope_node, source, &mut file_descriptors);

        // Check for fork() calls and subsequent fd usage
        self.check_for_fork_with_fd_usage(&scope_node, source, &file_descriptors, violations);
    }

    fn collect_file_descriptors(
        &self,
        node: &Node,
        source: &str,
        file_descriptors: &mut HashSet<Descriptor>,
    ) {
        for n in query::find_descendants(*node, |_| true) {
            if n.kind() == "init_declarator" {
                let (Some(declarator), Some(value)) = (
                    n.child_by_field_name("declarator"),
                    n.child_by_field_name("value"),
                ) else {
                    continue;
                };
                if !self.opens_file(&value, source) {
                    continue;
                }
                let Some(declaration) = n.parent() else {
                    continue;
                };
                if let Some(var_name) = self.extract_variable_name(&declarator, source) {
                    file_descriptors
                        .insert(Descriptor::Named(var_name, Some(declaration.start_byte())));
                }
            } else if n.kind() == "assignment_expression" {
                let (Some(left), Some(right)) = (
                    n.child_by_field_name("left"),
                    n.child_by_field_name("right"),
                ) else {
                    continue;
                };
                if !self.opens_file(&right, source) {
                    continue;
                }
                let left = strip_parens_and_casts(left);
                match left.kind() {
                    "identifier" => {
                        file_descriptors.insert(self.named_descriptor(&left, source));
                    }
                    "field_expression" => {
                        file_descriptors.insert(Descriptor::Path(token_text(&left, source)));
                    }
                    _ => {}
                }
            }
        }
    }

    /// True when `value` holds a call that resolves to one of
    /// [`OPEN_FUNCTIONS`], directly or as an argument of a wrapper.
    fn opens_file(&self, value: &Node, source: &str) -> bool {
        let project = self.project.borrow();
        query::find_descendants_of_kind(*value, "call_expression")
            .into_iter()
            .chain(std::iter::once(*value).filter(|v| v.kind() == "call_expression"))
            .any(|call| {
                let named = call
                    .child_by_field_name("function")
                    .is_some_and(|f| OPEN_FUNCTIONS.contains(&get_node_text(&f, source)));
                named
                    && thread_api::library_call(&call, source, project.as_ref())
                        .is_some_and(|name| OPEN_FUNCTIONS.contains(&name))
            })
    }

    /// The descriptor an identifier occurrence names: its spelling and the
    /// declaration it resolves to.
    fn named_descriptor(&self, ident: &Node, source: &str) -> Descriptor {
        let name = get_node_text(ident, source).to_string();
        let declaration =
            resolve_identifier_declarator(ident, &name, source).map(|(decl, _)| decl.start_byte());
        Descriptor::Named(name, declaration)
    }

    /// True when `expr` (an identifier or a field path) names one of
    /// `file_descriptors`.
    fn names_descriptor(
        &self,
        expr: &Node,
        source: &str,
        file_descriptors: &HashSet<Descriptor>,
    ) -> bool {
        let expr = strip_parens_and_casts(*expr);
        match expr.kind() {
            "identifier" => file_descriptors.contains(&self.named_descriptor(&expr, source)),
            "field_expression" => {
                file_descriptors.contains(&Descriptor::Path(token_text(&expr, source)))
            }
            _ => false,
        }
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
        file_descriptors: &HashSet<Descriptor>,
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
        file_descriptors: &HashSet<Descriptor>,
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
        file_descriptors: &HashSet<Descriptor>,
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
        file_descriptors: &HashSet<Descriptor>,
    ) -> bool {
        // Check for close() calls first - if fd is closed, it's not being used (safe pattern)
        if self.subtree_closes_file_descriptor(node, source, file_descriptors) {
            return false;
        }

        // A use is an identifier or field path in this subtree that names a
        // descriptor: resolved, so a shadowing local or the descriptor's
        // letters inside a string literal is not one.
        query::find_first_descendant(*node, |n| {
            matches!(n.kind(), "identifier" | "field_expression")
                && self.names_descriptor(&n, source, file_descriptors)
        })
        .is_some()
    }

    fn subtree_closes_file_descriptor(
        &self,
        node: &Node,
        source: &str,
        file_descriptors: &HashSet<Descriptor>,
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
            n.child_by_field_name("arguments")
                .and_then(|args| args.named_child(0))
                .is_some_and(|fd| self.names_descriptor(&fd, source, file_descriptors))
        })
        .is_some()
    }
}
