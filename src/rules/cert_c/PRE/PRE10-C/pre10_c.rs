// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! PRE10-C: Wrap multistatement macros in a do-while loop
//!
//! Multi-statement macros should be wrapped in do { ... } while(0) to prevent issues
//! when used in control structures without braces.
//!
//! ## Rationale:
//! - Without wrapping, macros used in if/else can cause unexpected behavior
//! - The do-while(0) idiom allows a trailing semicolon
//! - Prevents dangling else problems
//!
//! ## Example Non-compliant:
//! ```c
//! #define SWAP(x, y) tmp = x; x = y; y = tmp
//! if (z == 0) SWAP(a, b);  // Only first statement in if block!
//! ```
//!
//! ## Example Compliant:
//! ```c
//! #define SWAP(x, y) do { tmp = x; x = y; y = tmp; } while(0)
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pre10C;

/// What [`Pre10C::count_semicolons_outside_strings`] reads in a macro body.
struct Semicolons {
    /// Semicolons outside literals and `for` headers.
    count: usize,
    /// Whether the body has a `for` header.
    for_header: bool,
    /// Whether anything follows the last counted semicolon.
    text_after_last: bool,
}

impl CertRule for Pre10C {
    fn rule_id(&self) -> &'static str {
        "PRE10-C"
    }

    fn description(&self) -> &'static str {
        "Wrap multistatement macros in a do-while loop"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "PRE10-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Pre10C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for preprocessor macro definitions
        // preproc_def: object-like macros (e.g., #define MAX 100)
        // preproc_function_def: function-like macros with parameters (e.g., #define SWAP(x, y) ...)
        for n in query::find_descendants_of_kinds(*node, &["preproc_def", "preproc_function_def"]) {
            if let Some(value) = n.child_by_field_name("value") {
                let value_text = ast_utils::get_node_text(&value, source);

                // Check if this macro has multiple statements
                if self.has_multiple_statements(&value_text) {
                    // Check if it's wrapped in do-while(0)
                    if !self.is_wrapped_in_do_while(&value_text) {
                        // Get macro name for better error message
                        let macro_name = if let Some(name) = n.child_by_field_name("name") {
                            ast_utils::get_node_text(&name, source)
                        } else {
                            "unknown"
                        };

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: format!(
                                "Multistatement macro '{}' is not wrapped in a do-while loop. \
                                 This can cause issues when used in if statements without braces",
                                macro_name
                            ),
                            file_path: String::new(),
                            line: n.start_position().row + 1,
                            column: n.start_position().column + 1,
                            suggestion: Some(
                                "Wrap the macro body in: do { /* statements */ } while (0)"
                                    .to_string(),
                            ),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }
    }

    fn has_multiple_statements(&self, text: &str) -> bool {
        // Remove line continuations (backslash-newline)
        let cleaned = text.replace("\\\n", " ").replace("\\\r\n", " ");

        // Count semicolons (excluding those in strings and for headers).
        // A statement after a `for` statement's own semicolon is a second
        // statement even with no semicolon of its own, as in
        // `for (...) f(); g()`.
        let semicolons = self.count_semicolons_outside_strings(&cleaned);
        let semicolon_count = semicolons.count
            + usize::from(
                semicolons.for_header && semicolons.count > 0 && semicolons.text_after_last,
            );

        // Multiple statements if we have more than 1 semicolon
        // OR if we have curly braces (compound statement)
        if semicolon_count > 1 {
            return true;
        }

        // Check for curly braces pattern (like { x; y; z; })
        if cleaned.contains('{') && cleaned.contains('}') && semicolon_count > 0 {
            return true;
        }

        false
    }

    /// Semicolons that end a statement: outside string and character
    /// literals, and outside the parentheses of a `for` header, whose two
    /// semicolons separate its clauses, not statements.
    fn count_semicolons_outside_strings(&self, text: &str) -> Semicolons {
        let mut count = 0;
        let mut in_string = false;
        let mut in_char = false;
        let mut escaped = false;
        // The identifier or keyword just read, and whether the last token was `for`.
        let mut word = String::new();
        let mut after_for = false;
        // Parenthesis depth, and the depths at which a `for` header opened.
        let mut depth = 0usize;
        let mut for_headers: Vec<usize> = Vec::new();
        let mut for_header = false;
        let mut text_after_last = false;

        for c in text.chars() {
            if escaped {
                escaped = false;
                continue;
            }

            if c == '\\' {
                escaped = true;
                continue;
            }

            if in_string || in_char {
                if (c == '"' && in_string) || (c == '\'' && in_char) {
                    in_string = false;
                    in_char = false;
                }
                continue;
            }

            if c.is_ascii_alphanumeric() || c == '_' {
                word.push(c);
                text_after_last = true;
                continue;
            }
            if !word.is_empty() {
                after_for = word == "for";
                word.clear();
            }
            if c.is_whitespace() {
                continue;
            }

            text_after_last = true;
            match c {
                '"' => in_string = true,
                '\'' => in_char = true,
                '(' => {
                    depth += 1;
                    if after_for {
                        for_headers.push(depth);
                        for_header = true;
                    }
                }
                ')' => {
                    if for_headers.last() == Some(&depth) {
                        for_headers.pop();
                    }
                    depth = depth.saturating_sub(1);
                }
                ';' if for_headers.is_empty() => {
                    count += 1;
                    text_after_last = false;
                }
                _ => {}
            }
            after_for = false;
        }

        Semicolons {
            count,
            for_header,
            text_after_last,
        }
    }

    fn is_wrapped_in_do_while(&self, text: &str) -> bool {
        // Remove line continuations, collapse whitespace for robust matching
        let raw = text.replace("\\\r\n", " ").replace("\\\n", " ");
        let normalized: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");

        // Check for do-while(0) pattern
        let starts_with_do = normalized.starts_with("do {") || normalized.starts_with("do{");

        if !starts_with_do {
            return false;
        }

        // Accept both with and without trailing semicolon (some macros use `} while(0);`)
        let endings = [
            "while ( 0 )",
            "while(0)",
            "while (0)",
            "while( 0 )",
            "while ( 0 );",
            "while(0);",
            "while (0);",
            "while( 0 );",
        ];
        endings.iter().any(|e| normalized.ends_with(e))
    }
}
