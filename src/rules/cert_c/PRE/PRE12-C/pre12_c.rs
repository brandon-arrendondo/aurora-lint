// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::utility::cert_c::pp_tokens::define_at;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pre12C;

impl CertRule for Pre12C {
    fn rule_id(&self) -> &'static str {
        "PRE12-C"
    }
    fn description(&self) -> &'static str {
        "Do not define unsafe macros"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cert_id(&self) -> &'static str {
        "PRE12-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Pre12C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            // Look for preprocessor macro definitions. A comment in a
            // function-like macro's body can make tree-sitter read it as an
            // object-like one, so the directive's own text decides.
            if matches!(n.kind(), "preproc_function_def" | "preproc_def") {
                if let Some(param) = self.parameter_evaluated_twice(&n, source) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: n.start_position().row + 1,
                        column: n.start_position().column + 1,
                        file_path: String::new(),
                        message: format!("Macro evaluates parameter '{}' multiple times; use inline function instead", param),
                        suggestion: Some("Replace macro with inline function to avoid multiple evaluation".to_string()),
                        requires_manual_review: None,
                    });
                }
            }

            // Also detect expanded macro patterns: expressions with multiple side-effects
            // Pattern: (expr) ? -(expr) : (expr) where expr has side effects like ++n
            if n.kind() == "assignment_expression" || n.kind() == "conditional_expression" {
                let text = n.utf8_text(source.as_bytes()).unwrap_or("");

                // Check for increment/decrement operators appearing multiple times
                if text.contains("++") || text.contains("--") {
                    // Count occurrences of side-effect operators
                    let inc_count = text.matches("++").count() + text.matches("--").count();

                    // If there are 3+ occurrences, it's likely from macro expansion
                    if inc_count >= 3 && (text.contains('?') || text.contains(':')) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            line: n.start_position().row + 1,
                            column: n.start_position().column + 1,
                            file_path: String::new(),
                            message: "Expression with multiple side-effects; likely from unsafe macro expansion".to_string(),
                            suggestion: Some("Avoid passing expressions with side effects to macros".to_string()),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }
    }

    /// The first named parameter a function-like macro's body evaluates
    /// more than once. Only a plain use is an evaluation: not one inside a
    /// string or character literal or a comment, not the operand of `#` or
    /// `##` (spelled into the expansion, never evaluated), and not one inside
    /// `sizeof`, `_Alignof`, `typeof` or a `_Generic` controlling expression.
    /// A body using `__extension__` is skipped (GCC statement expressions
    /// that evaluate their arguments once).
    fn parameter_evaluated_twice(&self, node: &Node, source: &str) -> Option<String> {
        let define = define_at(node, source)?;
        let params = define.params.as_ref()?;
        let tokens = define.tokens();
        if tokens.iter().any(|t| t.text == "__extension__") {
            return None;
        }
        params
            .iter()
            .filter(|p| !p.ends_with("..."))
            .find(|p| {
                tokens
                    .iter()
                    .filter(|t| t.is_plain_use_of(p) && !t.unevaluated)
                    .count()
                    > 1
            })
            .cloned()
    }
}
