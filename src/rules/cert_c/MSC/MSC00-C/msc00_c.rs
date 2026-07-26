// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! MSC00-C: Compile cleanly at high warning levels
//!
//! This rule cannot statically evaluate a project's actual compiler warning
//! level or count real diagnostics -- that's a build-system concern outside
//! a single-file AST scan. It instead detects the one concrete, checkable
//! anti-pattern the wiki's own example shows: disabling a compiler warning
//! (`#pragma warning(disable:...)`, MSVC-style) without scoping the change
//! with a matching `#pragma warning(push)` / `#pragma warning(pop)` pair.
//! An unscoped disable silently suppresses that diagnostic for the rest of
//! the translation unit (or relies on a hand-paired `default:` restore that
//! is easy to omit or mismatch), defeating the "compile cleanly" goal for
//! any code that follows.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/MSC00-C.+Compile+cleanly+at+high+warning+levels

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Msc00C;

impl Msc00C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Msc00C
    }

    fn pragma_arg_text<'a>(&self, call: &Node, source: &'a str) -> Option<&'a str> {
        let mut cursor = call.walk();
        for child in call.children(&mut cursor) {
            if child.kind() == "preproc_arg" {
                return Some(ast_utils::get_node_text(&child, source).trim());
            }
        }
        None
    }

    fn traverse(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut push_depth: i32 = 0;

        let mut cursor = root.walk();
        for child in root.children(&mut cursor) {
            if child.kind() != "preproc_call" {
                continue;
            }
            let Some(arg) = self.pragma_arg_text(&child, source) else {
                continue;
            };
            if !arg.starts_with("warning(") {
                continue;
            }

            if arg.starts_with("warning(push") {
                push_depth += 1;
            } else if arg.starts_with("warning(pop") {
                push_depth = (push_depth - 1).max(0);
            } else if arg.starts_with("warning(disable:") && push_depth == 0 {
                let pos = child.start_position();
                violations.push(RuleViolation {
                    rule_id: "MSC00-C".to_string(),
                    severity: Severity::Low,
                    line: pos.row + 1,
                    column: pos.column + 1,
                    message:
                        "#pragma warning(disable:...) outside a push/pop scope permanently suppresses the diagnostic for the rest of the translation unit"
                            .to_string(),
                    file_path: String::new(),
                    suggestion: Some(
                        "Wrap the disable directive in #pragma warning(push) / #pragma warning(pop) so the suppression is scoped to the code that needs it"
                            .to_string(),
                    ),
                    requires_manual_review: Some(false),
                });
            }
        }
    }
}

impl CertRule for Msc00C {
    fn rule_id(&self) -> &'static str {
        "MSC00-C"
    }

    fn description(&self) -> &'static str {
        "Compile cleanly at high warning levels"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "MSC00-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
