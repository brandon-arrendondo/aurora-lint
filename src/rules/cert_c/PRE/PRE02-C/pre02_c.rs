// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! PRE02-C: Macro replacement lists should be parenthesized
//!
//! This rule addresses operator precedence issues when macros are used in expressions.
//! Without outer parentheses around the replacement list, operators in the macro can
//! interact unexpectedly with surrounding code.
//!
//! ## Non-compliant example:
//!
//! ```c
//! #define CUBE(X) (X) * (X) * (X)
//! int result = 81 / CUBE(i);  // Expands to 81 / (i) * (i) * (i) = wrong result!
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! #define CUBE(X) ((X) * (X) * (X))
//! int result = 81 / CUBE(i);  // Expands to 81 / ((i) * (i) * (i)) = correct!
//! ```
//!
//! ## Exceptions (No outer parentheses needed):
//!
//! 1. **Single identifier:**
//!    ```c
//!    #define MY_PID getpid()  // OK - single function call
//!    ```
//!
//! 2. **Array subscript:**
//!    ```c
//!    #define TOOFAR array[MAX_ARRAY_SIZE]  // OK - subscript operator
//!    ```
//!
//! 3. **Member access:**
//!    ```c
//!    #define NEXT_FREE block->next_free  // OK - member access
//!    ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::utility::cert_c::pp_tokens::{
    define_at, lex_replacement_list, PpKind, PpToken, KEYWORDS,
};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pre02C;

/// The replacement list as written, from its first token to its last:
/// comments inside it kept, a trailing one dropped.
fn as_written(body: &str, function_like: bool) -> &str {
    let tokens = lex_replacement_list(body, function_like);
    match (tokens.first(), tokens.last()) {
        (Some(first), Some(last)) => &body[first.start..last.end],
        _ => "",
    }
}

/// Binary operators whose precedence an unparenthesized replacement list
/// can lose to the operators around its expansion.
const BINARY_OPERATORS: &[&str] = &[
    "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", "&&", "||", "<", ">", "<=", ">=", "==",
    "!=",
];

/// Keywords that begin an operand (an expression), as opposed to a type,
/// a statement or a declaration.
const OPERAND_KEYWORDS: &[&str] = &[
    "sizeof",
    "_Alignof",
    "alignof",
    "__alignof__",
    "__alignof",
    "_Generic",
    "__extension__",
];

/// Whether the token at `k` ends an operand, making an operator after it
/// binary: `a - b`, `f(x) * 2`, `(int)-1`. A keyword does not (`return -1`,
/// `case -1:`, `char *`), nor does the tag after `struct`, `union` or `enum`
/// (`struct node *`); after those, or nothing, another operator or an
/// opening bracket, the operator is unary.
fn ends_operand(tokens: &[PpToken], k: usize) -> bool {
    let token = &tokens[k];
    match token.kind {
        PpKind::Identifier => {
            !KEYWORDS.contains(&token.text.as_ref())
                && !k
                    .checked_sub(1)
                    .is_some_and(|p| matches!(tokens[p].text.as_ref(), "struct" | "union" | "enum"))
        }
        PpKind::Number | PpKind::StringLiteral | PpKind::CharLiteral => true,
        PpKind::Punctuator => token.is(")") || token.is("]") || token.is("++") || token.is("--"),
        PpKind::Other => false,
    }
}

/// Whether `token` can begin an operand: a binary operator has one on each
/// side, so `STR_T char *` ends in a declarator's `*`, not a multiplication.
fn starts_operand(token: &PpToken) -> bool {
    match token.kind {
        PpKind::Identifier => {
            !KEYWORDS.contains(&token.text.as_ref())
                || OPERAND_KEYWORDS.contains(&token.text.as_ref())
        }
        PpKind::Number | PpKind::StringLiteral | PpKind::CharLiteral => true,
        PpKind::Punctuator => ["(", "-", "+", "!", "~", "*", "&", "++", "--"]
            .iter()
            .any(|p| token.is(p)),
        PpKind::Other => false,
    }
}

/// Whether the list opens a bracket it never closes. Such a list cannot be
/// one parenthesized expression, however its operators nest:
/// `((u32) (BIT(6) | BIT(7))` leaves the expansion's text to close it.
fn has_unclosed_bracket(tokens: &[PpToken]) -> bool {
    let mut depth = 0usize;
    for t in tokens {
        if t.is("(") || t.is("[") || t.is("{") {
            depth += 1;
        } else if t.is(")") || t.is("]") || t.is("}") {
            depth = depth.saturating_sub(1);
        }
    }
    depth > 0
}

/// Whether the replacement list has an operator at its top level, outside
/// every bracket: a binary operator (spaced or not) between two operands,
/// or a leading `-`, `!` or `~`, which the text before the expansion can
/// turn into a binary operator (`x END_OF_FILE` with `#define END_OF_FILE
/// -1`). A list that is one call, subscript or member access (EX1, EX2),
/// one parenthesized expression, a cast of one, or a `do { } while (0)`
/// has none: all its operators sit inside brackets. In a list with an
/// unclosed bracket every binary operator counts, since no pair of
/// brackets in it encloses the whole.
fn has_top_level_operator(tokens: &[PpToken]) -> bool {
    if tokens
        .first()
        .is_some_and(|t| t.is("-") || t.is("!") || t.is("~"))
    {
        return true;
    }
    let unclosed = has_unclosed_bracket(tokens);
    tokens.iter().enumerate().skip(1).any(|(k, t)| {
        (unclosed || t.depth == 0)
            && t.kind == PpKind::Punctuator
            && BINARY_OPERATORS.iter().any(|op| t.is(op))
            && ends_operand(tokens, k - 1)
            && tokens.get(k + 1).is_some_and(starts_operand)
    })
}

impl Pre02C {
    pub fn new() -> Self {
        Self
    }

    /// Check a macro definition for unparenthesized replacement list
    fn check_macro_definition(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // The directive's own tokens: an operator or parenthesis inside
        // `"a + b"`, `')'` or a comment is not code.
        let Some(define) = define_at(node, source) else {
            return;
        };
        let tokens = define.tokens();
        if !has_top_level_operator(&tokens) {
            return;
        }

        // Report violation
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message: "Macro replacement list should be parenthesized to prevent operator precedence issues.".to_string(),
            file_path: String::new(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            suggestion: Some(format!(
                "Wrap the entire replacement list in parentheses: ({})",
                as_written(define.body, define.params.is_some())
            )),
            ..Default::default()
        });
    }
}

impl CertRule for Pre02C {
    fn rule_id(&self) -> &'static str {
        "PRE02-C"
    }

    fn description(&self) -> &'static str {
        "Macro replacement lists should be parenthesized"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "PRE02-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for macro_node in
            query::find_descendants_of_kinds(*node, &["preproc_def", "preproc_function_def"])
        {
            self.check_macro_definition(&macro_node, source, &mut violations);
        }
        violations
    }
}
