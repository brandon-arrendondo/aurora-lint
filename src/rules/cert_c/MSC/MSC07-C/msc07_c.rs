// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! MSC07-C: Detect and remove code that is never executed
//!
//! Detects unreachable code patterns:
//! 1. Statements after unconditional return in the same block
//! 2. Statements after a call to a function that never returns: the shared
//!    noreturn set (`crate::analyze::noreturn`) the control-flow rules use,
//!    so `exit`/`abort` end a block only under `stdlib_noreturn`, and a
//!    project's own noreturn functions end it too
//! 3. Statements after unconditional break/continue/goto in the same block

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::noreturn::{self, ByNoreturnTrust};
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::Arc;
use tree_sitter::Node;

pub struct Msc07C {
    /// The prescan's cross-file noreturn functions
    /// (`ProjectContext::noreturn_functions`), under each noreturn setting.
    noreturn_functions: RefCell<ByNoreturnTrust<Arc<HashSet<String>>>>,
    /// The run's settings: which functions count as noreturn
    /// (`stdlib_noreturn`, `trust_noreturn_keyword`).
    settings: RefCell<Arc<AnalysisSettings>>,
}

impl Msc07C {
    pub fn new() -> Self {
        Self {
            noreturn_functions: RefCell::default(),
            settings: RefCell::default(),
        }
    }

    fn walk_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let settings = Arc::clone(&self.settings.borrow());
        let noreturn_names = noreturn::noreturn_names_for_file(
            self.noreturn_functions.borrow().get(&settings),
            node,
            source,
            &settings,
        );
        for compound in query::find_descendants_of_kind(*node, "compound_statement") {
            self.check_unreachable_after_terminal(&compound, source, &noreturn_names, violations);
        }
    }

    /// Scan children of a compound_statement. When we hit a terminal statement
    /// (return, break, continue, goto, or noreturn call), flag all subsequent
    /// non-trivial siblings as unreachable.
    fn check_unreachable_after_terminal(
        &self,
        compound: &Node,
        source: &str,
        noreturn_names: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let mut seen_terminal: Option<(&str, usize)> = None; // (kind_label, line)
                                                             // The previous sibling was a preprocessor block whose last token is
                                                             // a dangling `else` -- `} else` / `#endif` / `return X;` (mbedtls
                                                             // pkparse.c). The statement after it is that else's body, not an
                                                             // unconditional statement, however tree-sitter had to recover it.
        let mut after_dangling_else = false;

        for i in 0..compound.child_count() {
            let child = match compound.child(i) {
                Some(c) => c,
                None => continue,
            };

            // Skip braces, comments, and preprocessor directives
            if is_skippable(&child) {
                if ends_with_dangling_else(&child, source) {
                    after_dangling_else = true;
                }
                continue;
            }

            // A label or a case is reachable by construction: control
            // arrives by `goto` or by the switch dispatch, never from the
            // statement above it.
            if matches!(child.kind(), "labeled_statement" | "case_statement") {
                seen_terminal = None;
            }

            if let Some((terminal_kind, _)) = seen_terminal {
                // This statement is unreachable
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!("Unreachable code after unconditional '{}'.", terminal_kind,),
                    file_path: String::new(),
                    line: child.start_position().row + 1,
                    column: child.start_position().column + 1,
                    suggestion: Some(
                        "Remove the unreachable code or restructure the control flow".to_string(),
                    ),
                    ..Default::default()
                });
                // Only report the first unreachable statement per terminal
                break;
            }

            // Check if this child is a terminal statement. A label's own
            // statement is its last named child (`error: goto done;`), and
            // control does fall from it to the next sibling.
            let stmt = if child.kind() == "labeled_statement" {
                child.named_child(child.named_child_count().saturating_sub(1))
            } else {
                Some(child)
            };
            if let Some(label) = stmt.and_then(|n| terminal_label(&n, source, noreturn_names)) {
                if !after_dangling_else {
                    seen_terminal = Some((label, child.start_position().row + 1));
                }
            }
            after_dangling_else = false;
        }
    }
}

/// A preprocessor block whose recovered tail is an `else` with no body:
/// `} else` followed by `#endif` parses as an `ERROR` holding just `else`.
fn ends_with_dangling_else(node: &Node, source: &str) -> bool {
    if !node.kind().starts_with("preproc_") {
        return false;
    }
    let Some(last) = node.named_child(node.named_child_count().saturating_sub(1)) else {
        return false;
    };
    if last.kind() == "ERROR" {
        return get_node_text(&last, source).trim_end().ends_with("else");
    }
    ends_with_dangling_else(&last, source)
}

/// Returns a human-readable label if the node is a terminal (control never
/// passes to the next sibling).
fn terminal_label(
    node: &Node,
    source: &str,
    noreturn_names: &HashSet<String>,
) -> Option<&'static str> {
    match node.kind() {
        "return_statement" => Some("return"),
        "break_statement" => Some("break"),
        "continue_statement" => Some("continue"),
        "goto_statement" => Some("goto"),
        "expression_statement"
            if noreturn::is_noreturn_call_statement(node, source, noreturn_names) =>
        {
            Some("noreturn function call")
        }
        _ => None,
    }
}

/// Nodes that should be skipped when scanning for unreachable code.
fn is_skippable(node: &Node) -> bool {
    matches!(
        node.kind(),
        "{" | "}"
            | "comment"
            | "preproc_ifdef"
            | "preproc_if"
            | "preproc_else"
            | "preproc_elif"
            | "preproc_def"
            | "preproc_include"
            | "preproc_call"
    )
}

impl CertRule for Msc07C {
    fn rule_id(&self) -> &'static str {
        "MSC07-C"
    }

    fn description(&self) -> &'static str {
        "Detect and remove code that is never executed"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "MSC07-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.walk_node(node, source, violations);
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.noreturn_functions.borrow_mut() = context.noreturn_functions.clone();
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        *self.settings.borrow_mut() = Arc::clone(settings);
    }
}
