// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! PRE01-C: Use parentheses within macros around parameter names
//!
//! This rule addresses operator precedence issues in macro expansions.
//! Without parentheses around each parameter reference, complex expressions
//! passed as arguments can cause unexpected behavior due to operator precedence.
//!
//! ## Non-compliant example:
//!
//! ```c
//! #define CUBE(I) (I * I * I)
//! int result = 81 / CUBE(2 + 1);  // Expands to 81 / (2 + 1 * 2 + 1 * 2 + 1) = 11 (wrong!)
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! #define CUBE(I) ( (I) * (I) * (I) )
//! int result = 81 / CUBE(2 + 1);  // Expands to 81 / ( (2 + 1) * (2 + 1) * (2 + 1) ) = 3 (correct!)
//! ```
//!
//! ## Exceptions:
//!
//! 1. **Function call arguments**: Parameters already in comma-separated lists don't need parentheses:
//!    ```c
//!    #define FOO(a, b) bar(a, b)  // OK - commas have lower precedence
//!    ```
//!
//! 2. **Token concatenation (##) and stringification (#)**: These operators require un-parenthesized identifiers:
//!    ```c
//!    #define JOIN(a, b) (a ## b)  // OK - ## requires raw identifier
//!    #define SHOW(a) printf(#a " = %d\n", a)  // OK - # requires raw identifier
//!    ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::utility::cert_c::pp_tokens::{define_at, PpToken};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pre01C;

impl Pre01C {
    pub fn new() -> Self {
        Self
    }

    /// Whether the parameter use at `k` needs no parentheses: it is already
    /// parenthesized, or it is followed by `,` or `)` inside some `(` (a
    /// function-call argument; commas have the lowest precedence).
    fn is_exempt_position(tokens: &[PpToken], k: usize) -> bool {
        let prev = k.checked_sub(1).map(|p| &tokens[p]);
        let next = tokens.get(k + 1);
        let closes = next.is_some_and(|t| t.is(")"));
        if prev.is_some_and(|t| t.is("(")) && closes {
            return true;
        }
        let mut depth = 0usize;
        let inside_parens = tokens[..k].iter().rev().any(|t| {
            if t.is(")") {
                depth += 1;
            } else if t.is("(") {
                if depth == 0 {
                    return true;
                }
                depth -= 1;
            }
            false
        });
        inside_parens && (closes || next.is_some_and(|t| t.is(",")))
    }

    /// Check a function-like macro definition for unparenthesized parameters
    fn check_function_macro(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // The directive's own text, not tree-sitter's fields: a comment in a
        // function-like macro's body can make it misparse the directive.
        let Some(define) = define_at(node, source) else {
            return;
        };
        let Some(params) = &define.params else {
            return;
        };
        let tokens = define.tokens();

        // Every use of each parameter in the replacement list. A spelling in
        // a string or character literal or a comment is not a use, and the
        // operand of `#` or `##` must stay a bare identifier.
        for param in params.iter().filter(|p| !p.ends_with("...")) {
            let unparenthesized = tokens
                .iter()
                .enumerate()
                .any(|(k, t)| t.is_plain_use_of(param) && !Self::is_exempt_position(&tokens, k));
            if unparenthesized {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Macro parameter '{}' is not parenthesized in replacement text. This can cause operator precedence issues.",
                        param
                    ),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(format!(
                        "Wrap parameter '{}' in parentheses: ({}) instead of {}",
                        param, param, param
                    )),
                    ..Default::default()
                });
            }
        }
    }
}

impl CertRule for Pre01C {
    fn rule_id(&self) -> &'static str {
        "PRE01-C"
    }

    fn description(&self) -> &'static str {
        "Use parentheses within macros around parameter names"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "PRE01-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for macro_node in
            query::find_descendants_of_kinds(*node, &["preproc_function_def", "preproc_def"])
        {
            self.check_function_macro(&macro_node, source, &mut violations);
        }
        violations
    }
}
