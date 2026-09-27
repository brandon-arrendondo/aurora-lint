// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::utility::cert_c::pp_tokens::{define_at, matching_close, DefineDirective, PpToken};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pre00C;

impl CertRule for Pre00C {
    fn rule_id(&self) -> &'static str {
        "PRE00-C"
    }

    fn description(&self) -> &'static str {
        "Prefer inline or static functions to function-like macros"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        self.rule_id()
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(root, source, violations);
    }
}

impl Pre00C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Only flag function-like macros with parameters that are evaluated
        // more than once (multi-evaluation risk). A comment in the body can
        // make tree-sitter read one as a `preproc_def`, so the directive's
        // own text says which it is.
        for n in query::find_descendants_of_kinds(*node, &["preproc_function_def", "preproc_def"]) {
            let Some(define) = define_at(&n, source) else {
                continue;
            };
            if self.has_multi_evaluation_risk(&define) {
                let macro_name = define.name;
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Function-like macro '{}' evaluates parameter(s) multiple times; \
                         prefer inline or static functions for type safety",
                        macro_name
                    ),
                    file_path: String::new(),
                    line: n.start_position().row + 1,
                    column: n.start_position().column + 1,
                    suggestion: None,
                    requires_manual_review: None,
                });
            }
        }
    }

    /// Check if a function-like macro has unsafe patterns: multi-evaluation
    /// of parameters or side effects in the body.
    ///
    /// Read over the body's tokens, so nothing inside a string or character
    /// literal or a comment counts, and neither does the operand of `#` or
    /// `##`. Nor does anything inside the operand of `sizeof`, `_Alignof`,
    /// `typeof` or a `_Generic` controlling expression, or the arguments of
    /// `__builtin_types_compatible_p`: those are never evaluated at runtime,
    /// unlike a real repeated use in a comparison, arithmetic expression, or
    /// function-call argument. This is the idiom curl's typecheck-gcc.h
    /// helper macros use throughout (e.g. `curlcheck_long`/`curlcheck_ptr`:
    /// every repeated reference to `expr` sits inside `__typeof__(expr)`).
    fn has_multi_evaluation_risk(&self, define: &DefineDirective) -> bool {
        let Some(params) = &define.params else {
            return false;
        };
        let mut tokens = define.tokens();
        mark_type_only_arguments(&mut tokens);
        let evaluated = |t: &&PpToken| !t.unevaluated;

        // Side effects in body: increment/decrement operators
        if tokens
            .iter()
            .filter(evaluated)
            .any(|t| t.is("++") || t.is("--"))
        {
            return true;
        }

        // Multi-evaluation: any parameter used more than once.
        params.iter().filter(|p| !p.ends_with("...")).any(|param| {
            tokens
                .iter()
                .filter(evaluated)
                .filter(|t| t.is_plain_use_of(param))
                .count()
                > 1
        })
    }
}

/// Mark the arguments of `__builtin_types_compatible_p(...)` unevaluated:
/// GCC compares their types and never evaluates them.
fn mark_type_only_arguments(tokens: &mut [PpToken]) {
    for k in 0..tokens.len() {
        if tokens[k].text == "__builtin_types_compatible_p"
            && tokens.get(k + 1).is_some_and(|t| t.is("("))
        {
            if let Some(close) = matching_close(tokens, k + 1) {
                tokens[k + 2..close]
                    .iter_mut()
                    .for_each(|t| t.unevaluated = true);
            }
        }
    }
}
