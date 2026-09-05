// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! MSC23-C: Beware of vendor-specific library and language differences
//!
//! This is a broad, CWE-less recommendation with no single checkable defect
//! -- the wiki's own guidance is "read your vendor's documentation." The one
//! concretely checkable example it gives is text-mode `fopen()`/`freopen()`:
//! on a vendor whose C runtime does newline translation in text mode (the
//! canonical case being CRLF -> LF on Windows), a loop that counts bytes
//! read from a text-mode stream gets a vendor-dependent count that differs
//! from the file's actual byte size.
//!
//! Flagging every text-mode `fopen()`/`freopen()` call was tried and
//! reverted (task 347): text mode is the overwhelmingly common, correct
//! idiom on POSIX targets (grepping sqlite/mosquitto/curl found 160+ such
//! calls with no corresponding real defect), so a blanket check is a major
//! false-positive source for a rule with no CWE and no benchmark presence
//! to justify the noise. This narrows to the wiki's actual failure mode:
//! a text-mode open whose stream is then read one character at a time via
//! `fgetc()`/`getc()` in a loop that also unconditionally increments a
//! counter every iteration -- exactly the wiki's own noncompliant example
//! (`++counter; (void)fgetc(fp);`).
//!
//! The read/counter co-occurrence check was initially looser (any
//! stream-read call anywhere in a loop, alongside any increment of any
//! other variable anywhere in that loop), but spot-checking the pinned
//! real-world corpora (task 347/419) turned up several false positives
//! that shape doesn't distinguish from a genuine byte counter:
//!   - `fgets()`-based line readers where an unrelated pointer walk in a
//!     *nested* loop happens to use `++` (sqlite's `sqllogFindFile`,
//!     hostap's `history_read` CRLF-stripping loop) -- fixed by requiring
//!     the read to be a single-character function (`fgetc`/`getc`/
//!     `fgetwc`/`getwc`), since a `size_t`/line-count from `fgets`/`fread`
//!     isn't the direct 1-read-1-byte tracker the wiki example depends on.
//!   - an unrelated `+=`/nested-conditional increment elsewhere in the same
//!     loop (mosquitto's `cmd += 1` pointer skip, pure-ftpd's bounded
//!     `instamp++` timestamp-digit index, raylib's per-match `count++`) --
//!     fixed by requiring the counter increment to be a bare, unconditional
//!     `x++;`/`++x;` statement directly in the loop body, not `+=` and not
//!     nested inside a further conditional or loop.
//!
//! Both narrowings trade recall for precision deliberately: this rule has
//! no CWE and no benchmark ground truth to delta-adjudicate against, so a
//! speculative match that turns out wrong has no cheap way to be caught
//! later -- see the Protocol section of CLAUDE.md.
//!
//! CERT C reference:
//! <https://wiki.sei.cmu.edu/confluence/display/c/MSC23-C.+Beware+of+vendor-specific+library+and+language+differences>

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{get_identifier_from_declarator, get_node_text};
use lang_parsing_substrate::query;
use tree_sitter::Node;

/// Single-character stream-reading functions: one call reads exactly one
/// character/wide-character, so an unconditional per-iteration counter
/// alongside one of these is a direct byte-position tracker -- unlike
/// `fgets`/`fread`, which read a variable/multi-byte amount per call and
/// whose surrounding counters usually track something else (lines,
/// matches, parsed fields) that text-mode translation doesn't affect the
/// same way.
const STREAM_READ_FNS: &[&str] = &["fgetc", "getc", "fgetwc", "getwc"];

#[derive(Debug)]
pub struct Msc23C;

impl Msc23C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Msc23C
    }

    /// The variable a `call_expression`'s result is assigned to, via either
    /// a declaration initializer (`FILE *fp = fopen(...)`) or a plain
    /// assignment (`fp = fopen(...)`). `None` for any other context (e.g.
    /// the return value is passed straight to another call, or discarded)
    /// -- without a named variable there's nothing to trace into a later
    /// loop.
    fn assigned_variable(&self, call: &Node, source: &str) -> Option<String> {
        let parent = call.parent()?;
        match parent.kind() {
            "init_declarator" => {
                let declarator = parent.child_by_field_name("declarator")?;
                let name = get_identifier_from_declarator(&declarator, source);
                (!name.is_empty()).then_some(name)
            }
            "assignment_expression" => {
                let left = parent.child_by_field_name("left")?;
                (left.kind() == "identifier").then(|| get_node_text(&left, source).to_string())
            }
            _ => None,
        }
    }

    /// The `fopen`/`freopen` mode-string argument, if it's a literal (not a
    /// macro or variable -- those are left alone, since the mode can't be
    /// determined statically).
    fn mode_literal<'a>(&self, call: &Node<'a>, source: &str) -> Option<(Node<'a>, String)> {
        let args = call.child_by_field_name("arguments")?;
        let mode_arg = args.named_child(1)?;
        if mode_arg.kind() != "string_literal" {
            return None;
        }
        let text = get_node_text(&mode_arg, source);
        Some((mode_arg, text.trim_matches('"').to_string()))
    }

    /// True if any argument of `call` is a bare identifier named `var_name`.
    fn call_references_var(&self, call: &Node, var_name: &str, source: &str) -> bool {
        let Some(args) = call.child_by_field_name("arguments") else {
            return false;
        };
        (0..args.named_child_count()).any(|i| {
            args.named_child(i)
                .is_some_and(|a| a.kind() == "identifier" && get_node_text(&a, source) == var_name)
        })
    }

    /// True if `node` is a stream-read call (`fgetc`, `fread`, ...) on
    /// `var_name`.
    fn is_stream_read_of(&self, node: &Node, var_name: &str, source: &str) -> bool {
        node.kind() == "call_expression"
            && node
                .child_by_field_name("function")
                .is_some_and(|f| STREAM_READ_FNS.contains(&get_node_text(&f, source)))
            && self.call_references_var(node, var_name, source)
    }

    /// True if `stmt` is exactly a bare `x++;`/`++x;`/`x--;`/`--x;`
    /// expression statement on some variable other than the stream itself
    /// (incrementing the `FILE *` pointer isn't a byte count). Deliberately
    /// does not match `x += n` or an increment nested inside a further
    /// `if`/loop -- see the module doc for the false positives that
    /// distinction rules out. A statement matching this shape executes
    /// exactly once per loop iteration, unconditionally, mirroring the
    /// wiki's own `++counter;`.
    fn is_bare_counter_increment(&self, stmt: &Node, var_name: &str, source: &str) -> bool {
        if stmt.kind() != "expression_statement" {
            return false;
        }
        let Some(expr) = stmt.named_child(0) else {
            return false;
        };
        expr.kind() == "update_expression"
            && expr.child_by_field_name("argument").is_some_and(|arg| {
                arg.kind() == "identifier" && get_node_text(&arg, source) != var_name
            })
    }

    /// The loop body's direct statement children (skipping `{`/`}`), or a
    /// single-element list holding `body` itself when the loop has no
    /// braces (`for (...) stmt;`).
    fn top_level_statements<'a>(&self, loop_body: &Node<'a>) -> Vec<Node<'a>> {
        if loop_body.kind() != "compound_statement" {
            return vec![*loop_body];
        }
        (0..loop_body.child_count())
            .filter_map(|i| loop_body.child(i))
            .filter(|c| !matches!(c.kind(), "{" | "}"))
            .collect()
    }

    /// True if some loop in `body` both reads `var_name` one character at a
    /// time and unconditionally increments a counter every iteration --
    /// the wiki's "counted characters read from a stream opened without
    /// 'b'" pattern (`++counter; (void)fgetc(fp);`). Both conditions are
    /// checked against the loop's own top-level statements, not its full
    /// subtree, so an unrelated read/increment nested one level deeper (a
    /// sub-loop, an `if`) can't satisfy either half -- see the module doc.
    fn has_byte_counting_loop(&self, body: &Node, var_name: &str, source: &str) -> bool {
        let loop_kinds = ["while_statement", "for_statement", "do_statement"];
        query::find_descendants_of_kinds(*body, &loop_kinds)
            .into_iter()
            .filter_map(|loop_node| loop_node.child_by_field_name("body"))
            .any(|loop_body| {
                let stmts = self.top_level_statements(&loop_body);
                let reads = stmts.iter().any(|s| {
                    query::find_first_descendant(*s, |n| {
                        self.is_stream_read_of(&n, var_name, source)
                    })
                    .is_some()
                });
                let counts = stmts
                    .iter()
                    .any(|s| self.is_bare_counter_increment(s, var_name, source));
                reads && counts
            })
    }
}

impl CertRule for Msc23C {
    fn rule_id(&self) -> &'static str {
        "MSC23-C"
    }

    fn description(&self) -> &'static str {
        "Beware of vendor-specific library and language differences"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "MSC23-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        for func in query::find_descendants_of_kind(*node, "function_definition") {
            let Some(body) = func.child_by_field_name("body") else {
                continue;
            };

            for call in query::find_descendants_of_kind(body, "call_expression") {
                let Some(func_name_node) = call.child_by_field_name("function") else {
                    continue;
                };
                let func_name = get_node_text(&func_name_node, source);
                if func_name != "fopen" && func_name != "freopen" {
                    continue;
                }

                let Some((mode_node, mode)) = self.mode_literal(&call, source) else {
                    continue;
                };
                // Text mode, opened for reading: no 'b', and 'r' present
                // ("r", "r+", "rt", ...). Write-only text modes aren't
                // byte-counting-read candidates.
                if mode.contains('b') || !mode.contains('r') {
                    continue;
                }

                let Some(var_name) = self.assigned_variable(&call, source) else {
                    continue;
                };

                if self.has_byte_counting_loop(&body, &var_name, source) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: format!(
                            "'{}' is opened in text mode (\"{}\") and then read byte-by-byte in a loop that counts bytes; vendor-specific newline translation (e.g. CRLF -> LF) can make the count differ from the file's actual size.",
                            var_name, mode
                        ),
                        file_path: String::new(),
                        line: mode_node.start_position().row + 1,
                        column: mode_node.start_position().column + 1,
                        suggestion: Some(format!(
                            "Open '{}' in binary mode (\"{}b\") if an exact byte count is required.",
                            var_name, mode
                        )),
                        ..Default::default()
                    });
                }
            }
        }

        violations
    }
}
