// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! FIO14-C: Understand the difference between text mode and binary mode with file streams
//!
//! This rule detects improper use of file positioning functions with text/binary streams:
//!
//! ## Text Mode Issues:
//! - Using arbitrary offsets with fseek() (only 0 or ftell() values allowed with SEEK_SET)
//! - File position is indeterminate after ungetc() until pushed-back characters are read
//!
//! ## Binary Mode Issues:
//! - Using fseek() with SEEK_END (binary streams may have unspecified null termination)
//! - Calling ungetc() when file position indicator is 0
//!
//! ## Detected Violations:
//! - fseek() with non-zero offset in text mode (without prior ftell())
//! - fseek() with SEEK_END on binary mode files
//! - ungetc() on a stream nothing has read or positioned since it was opened
//!
//! ## Compliant Patterns:
//! - Using binary mode ("rb", "wb") for binary data
//! - Using text mode ("r", "w") for text data with appropriate positioning
//! - Using fseek() with 0 or ftell() values in text mode
//!
//! ## Stream mode:
//! A finding needs the stream's mode: the stream argument must resolve, by
//! its declaration (ADR-0006), to an fopen()/freopen()/fopen_s() whose mode is a string
//! literal, and every such open of it must agree on text or binary. A stream
//! whose mode is not known (a parameter, a member, a mode chosen at run time)
//! is not reported, nor is either `fseek` form when POSIX holds, where text
//! and binary streams are the same.
//!
//! ## ungetc() at file position 0:
//! Reported in every environment. ISO C leaves a binary stream's position
//! indeterminate after it (C11 7.21.7.10p5) and a text stream's unspecified
//! after any ungetc(); POSIX keeps the position-0 clause and applies it to
//! every stream. The position is known to be 0 only conservatively: the
//! write every path to the call runs last is an fopen()/freopen()/fopen_s()
//! of the stream with a literal, non-append mode, and the stream is not used
//! between that open and the call (nor in a loop around the call that does
//! not also hold the open) except to test it against NULL.

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::{ancestors, get_node_text, resolve_identifier_declarator};
use crate::utility::cert_c::guard_dominance::{dominating_write, Dominating, WriteIndex};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::sync::Arc;
use tree_sitter::Node;

#[derive(Default)]
pub struct Fio14C {
    settings: RefCell<Arc<AnalysisSettings>>,
}

/// How a stream was opened.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamMode {
    Text,
    Binary,
}

impl CertRule for Fio14C {
    fn rule_id(&self) -> &'static str {
        "FIO14-C"
    }

    fn description(&self) -> &'static str {
        "Understand the difference between text mode and binary mode with file streams"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "FIO14-C"
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        *self.settings.borrow_mut() = Arc::clone(settings);
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Under POSIX 'b' has no effect, which relaxes both fseek() forms but
        // not ungetc() at position 0.
        let posix = self.settings.borrow().posix_holds_project();
        self.check_node(node, source, posix, violations);
    }
}

impl Fio14C {
    fn check_node(
        &self,
        node: &Node,
        source: &str,
        posix: bool,
        violations: &mut Vec<RuleViolation>,
    ) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                match get_node_text(&function, source) {
                    "fseek" if !posix => self.check_fseek_call(&call, source, violations),
                    "ungetc" => self.check_ungetc_call(&call, source, violations),
                    _ => {}
                }
            }
        }
    }

    /// Check an ungetc() call on a stream still at file position 0.
    fn check_ungetc_call(&self, call: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let Some(arguments) = call.child_by_field_name("arguments") else {
            return;
        };
        let args = self.extract_arguments(&arguments, source);
        let [pushed, stream] = args.as_slice() else {
            return;
        };
        // ungetc(EOF, stream) fails and leaves the stream unchanged
        // (C11 7.21.7.10p4).
        if get_node_text(pushed, source).trim() == "EOF" {
            return;
        }
        let stream = strip_parens(*stream);
        if stream.kind() != "identifier" {
            return;
        }
        let name = get_node_text(&stream, source);
        let Some((decl, _)) = resolve_identifier_declarator(&stream, name, source) else {
            return;
        };
        let is_stream = |n: &Node| {
            n.kind() == "identifier"
                && get_node_text(n, source) == name
                && resolve_identifier_declarator(n, name, source)
                    .is_some_and(|(d, _)| d.id() == decl.id())
        };
        let Some(body) = ancestors(call)
            .find(|a| a.kind() == "function_definition")
            .and_then(|f| f.child_by_field_name("body"))
        else {
            return;
        };
        let index = WriteIndex::new(&body, source);
        let Some(found) = dominating_write(name, call, source, &index, |stmt| {
            open_in_statement(stmt, source, &is_stream).map(Some)
        }) else {
            return;
        };
        let open = match found {
            Dominating::Assignment(a) => strip_parens(a.value),
            Dominating::Other(open) => open,
        };
        if !opens_at_start(&open, source) {
            return;
        }

        // Nothing may read, write or position the stream after the open: not
        // between it and the call, not in the call's own first argument
        // (`ungetc(fgetc(fp), fp)`), and not anywhere in a loop around the
        // call that does not also hold the open (its back edge).
        let mut regions = vec![(open.end_byte(), call.start_byte()), byte_range(pushed)];
        for a in ancestors(call).take_while(|a| a.id() != body.id()) {
            if matches!(
                a.kind(),
                "for_statement" | "while_statement" | "do_statement"
            ) && !(a.start_byte() <= open.start_byte() && open.end_byte() <= a.end_byte())
            {
                regions.push(byte_range(&a));
            }
        }
        let moves_stream = query::find_descendants(body, |n| {
            regions
                .iter()
                .any(|&(lo, hi)| lo <= n.start_byte() && n.end_byte() <= hi)
                && is_stream(&n)
                && !only_tests_stream(&n, source)
        });
        if !moves_stream.is_empty() {
            return;
        }

        let start_point = call.start_position();
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::Medium,
            message: format!(
                "ungetc() on '{}' at file position 0: nothing has read or positioned the stream since it was opened, so neither ISO C nor POSIX says where its file position is after the call",
                name
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(
                "Read from the stream before pushing a character back onto it".to_string(),
            ),
            ..Default::default()
        });
    }

    /// Check fseek() calls for improper usage
    fn check_fseek_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // fseek(stream, offset, whence)
        if let Some(arguments) = node.child_by_field_name("arguments") {
            let args = self.extract_arguments(&arguments, source);

            if args.len() >= 3 {
                let Some(mode) = stream_mode(&args[0], source) else {
                    return;
                };
                let offset_text = get_node_text(&args[1], source);
                let whence_text = get_node_text(&args[2], source);

                // Check for SEEK_END usage (problematic in binary mode)
                if whence_text == "SEEK_END" && mode == StreamMode::Binary {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: "fseek() with SEEK_END should not be used on binary streams (undefined behavior with null padding)".to_string(),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Use SEEK_SET or SEEK_CUR instead, or ensure stream is in text mode"
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                }

                // Check for non-zero offset with SEEK_SET (problematic in text mode)
                // This is a heuristic - we flag literal non-zero offsets
                if whence_text == "SEEK_SET"
                    && mode == StreamMode::Text
                    && self.is_literal_nonzero_offset(offset_text)
                {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "fseek() with arbitrary offset '{}' and SEEK_SET may not work correctly in text mode (only 0 or ftell() values allowed)",
                            offset_text
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Use binary mode for the file, or use offset from ftell()".to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Extract function call arguments as a vector of nodes
    fn extract_arguments<'a>(&self, arguments_node: &Node<'a>, _source: &str) -> Vec<Node<'a>> {
        let mut args = Vec::new();

        for i in 0..arguments_node.child_count() {
            if let Some(child) = arguments_node.child(i) {
                // Skip commas and parentheses
                if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                    args.push(child);
                }
            }
        }

        args
    }

    /// Check if an offset is a literal non-zero value (not a function call or variable)
    fn is_literal_nonzero_offset(&self, offset_text: &str) -> bool {
        // Try to parse as integer
        if let Ok(value) = offset_text.trim().parse::<i64>() {
            value != 0
        } else {
            // Not a simple integer literal, might be ftell() or a variable
            false
        }
    }
}

/// The mode of the stream `arg` names: the mode literal of every
/// fopen()/freopen()/fopen_s() that opens the variable it resolves to, when
/// they agree.
fn stream_mode(arg: &Node, source: &str) -> Option<StreamMode> {
    let mut ident = *arg;
    while ident.kind() == "parenthesized_expression" {
        ident = ident.named_child(0)?;
    }
    if ident.kind() != "identifier" {
        return None;
    }
    let name = get_node_text(&ident, source);
    let (decl, _) = resolve_identifier_declarator(&ident, name, source)?;
    let same_variable = |n: &Node| {
        n.kind() == "identifier"
            && get_node_text(n, source) == name
            && resolve_identifier_declarator(n, name, source)
                .is_some_and(|(d, _)| d.id() == decl.id())
    };

    let mut modes = Vec::new();
    // `FILE *fp = fopen(...)`
    let mut d = decl.child_by_field_name("declarator");
    while let Some(declarator) = d {
        if declarator.kind() == "init_declarator"
            && query::find_first_descendant(declarator, |n| n.kind() == "identifier")
                .is_some_and(|n| get_node_text(&n, source) == name)
        {
            // An initializer that opens nothing (`= NULL`) says nothing of the mode.
            if let Some(value) = declarator
                .child_by_field_name("value")
                .filter(|v| matches!(callee(v, source), Some("fopen" | "freopen")))
            {
                modes.push(open_mode(&value, source));
            }
        }
        d = declarator.next_named_sibling();
    }
    let root = {
        let mut r = decl;
        while let Some(p) = r.parent() {
            r = p;
        }
        r
    };
    // `fp = fopen(...)`, `freopen(path, mode, fp)` and `fopen_s(&fp, path, mode)`
    for n in query::find_descendants(root, |n| {
        matches!(n.kind(), "assignment_expression" | "call_expression")
    }) {
        if n.kind() == "assignment_expression" {
            let (Some(left), Some(right)) = (
                n.child_by_field_name("left"),
                n.child_by_field_name("right"),
            ) else {
                continue;
            };
            if matches!(callee(&right, source), Some("fopen" | "freopen")) && same_variable(&left) {
                modes.push(open_mode(&right, source));
            }
        } else if callee(&n, source) == Some("freopen") {
            let stream = n
                .child_by_field_name("arguments")
                .and_then(|a| a.named_child(2));
            if stream.is_some_and(|s| same_variable(&s)) {
                modes.push(open_mode(&n, source));
            }
        } else if callee(&n, source) == Some("fopen_s") {
            let stream = n
                .child_by_field_name("arguments")
                .and_then(|a| a.named_child(0))
                .filter(|a| {
                    a.kind() == "pointer_expression"
                        && a.child_by_field_name("operator")
                            .is_some_and(|op| get_node_text(&op, source) == "&")
                })
                .and_then(|a| a.child_by_field_name("argument"));
            if stream.is_some_and(|s| same_variable(&s)) {
                modes.push(open_mode(&n, source));
            }
        }
    }

    let first = (*modes.first()?)?;
    modes.iter().all(|m| *m == Some(first)).then_some(first)
}

fn strip_parens(mut node: Node) -> Node {
    while node.kind() == "parenthesized_expression" {
        match node.named_child(0) {
            Some(inner) => node = inner,
            None => break,
        }
    }
    node
}

fn byte_range(node: &Node) -> (usize, usize) {
    (node.start_byte(), node.end_byte())
}

/// The open of the stream a statement runs on every path through it, for
/// the forms `dominating_write` does not read as an assignment:
/// `freopen(path, mode, fp);`, `fopen_s(&fp, path, mode);`, and an `if`
/// whose condition opens the stream outside any `&&`, `||` or `?:` operand
/// (`if ((fp = fopen(path, "r")) == NULL) return;`).
fn open_in_statement<'a>(
    stmt: &Node<'a>,
    source: &str,
    is_stream: &dyn Fn(&Node) -> bool,
) -> Option<Node<'a>> {
    let expr = match stmt.kind() {
        "expression_statement" => stmt.named_child(0)?,
        "if_statement" => stmt.child_by_field_name("condition")?,
        _ => return None,
    };
    let mut stack = vec![expr];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "parenthesized_expression" | "condition_clause" | "unary_expression" => {
                stack.extend(node.named_children(&mut node.walk()));
            }
            "binary_expression" => {
                let op = node.child_by_field_name("operator")?;
                if matches!(get_node_text(&op, source), "&&" | "||") {
                    // Only the left operand runs on every path.
                    stack.extend(node.child_by_field_name("left"));
                } else {
                    stack.extend(node.named_children(&mut node.walk()));
                }
            }
            "assignment_expression" if stmt.kind() == "if_statement" => {
                let (left, right) = (
                    node.child_by_field_name("left")?,
                    strip_parens(node.child_by_field_name("right")?),
                );
                if is_stream(&strip_parens(left))
                    && matches!(callee(&right, source), Some("fopen" | "freopen"))
                {
                    return Some(right);
                }
            }
            "call_expression" => {
                let args = node.child_by_field_name("arguments")?;
                let opened = match callee(&node, source)? {
                    "freopen" => args.named_child(2),
                    "fopen_s" => args
                        .named_child(0)
                        .filter(|a| {
                            a.kind() == "pointer_expression"
                                && a.child_by_field_name("operator")
                                    .is_some_and(|op| get_node_text(&op, source) == "&")
                        })
                        .and_then(|a| a.child_by_field_name("argument")),
                    _ => None,
                };
                if opened.is_some_and(|s| is_stream(&strip_parens(s))) {
                    return Some(node);
                }
            }
            _ => {}
        }
    }
    None
}

/// Whether an open leaves its stream at file position 0 for input: its
/// mode is a literal that reads (`r`, or any update mode) and does not
/// append, since where an append-mode stream starts is
/// implementation-defined (C11 7.21.3p1).
fn opens_at_start(open: &Node, source: &str) -> bool {
    if !matches!(callee(open, source), Some("fopen" | "freopen" | "fopen_s")) {
        return false;
    }
    let Some(mode) = opener_mode_arg(open, source).filter(|m| m.kind() == "string_literal") else {
        return false;
    };
    let text = get_node_text(&mode, source);
    let Some(body) = text.strip_prefix('"').and_then(|t| t.strip_suffix('"')) else {
        return false;
    };
    body.starts_with('r') || (body.contains('+') && !body.starts_with('a'))
}

/// A use of the stream that cannot move it: a test against NULL or of its
/// truth (`fp == NULL`, `!fp`, `if (fp)`, `fp && ...`).
fn only_tests_stream(ident: &Node, source: &str) -> bool {
    let mut node = *ident;
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "parenthesized_expression" => node = parent,
            "binary_expression" => {
                return parent.child_by_field_name("operator").is_some_and(|op| {
                    matches!(get_node_text(&op, source), "==" | "!=" | "&&" | "||")
                });
            }
            "unary_expression" => {
                return parent
                    .child_by_field_name("operator")
                    .is_some_and(|op| get_node_text(&op, source) == "!");
            }
            "condition_clause" | "if_statement" | "while_statement" | "do_statement" => {
                return true;
            }
            _ => return false,
        }
    }
    false
}

fn callee<'a>(call: &Node, source: &'a str) -> Option<&'a str> {
    if call.kind() != "call_expression" {
        return None;
    }
    Some(get_node_text(
        &call.child_by_field_name("function")?,
        source,
    ))
}

/// The mode argument of an fopen(), freopen() or fopen_s() call.
fn opener_mode_arg<'a>(call: &Node<'a>, source: &str) -> Option<Node<'a>> {
    match callee(call, source)? {
        "fopen" | "freopen" => call.child_by_field_name("arguments")?.named_child(1),
        "fopen_s" => call.child_by_field_name("arguments")?.named_child(2),
        _ => None,
    }
}

/// The mode an fopen()/freopen()/fopen_s() call opens with, when its mode is a string
/// literal (C11 7.21.5.3: a `b` anywhere in it makes the stream binary).
fn open_mode(call: &Node, source: &str) -> Option<StreamMode> {
    let mode = opener_mode_arg(call, source)?;
    if mode.kind() != "string_literal" {
        return None;
    }
    let text = get_node_text(&mode, source);
    let body = text.strip_prefix('"')?.strip_suffix('"')?;
    Some(if body.contains('b') {
        StreamMode::Binary
    } else {
        StreamMode::Text
    })
}
