// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! FIO39-C: Do not alternately input and output from a stream without an intervening flush or positioning call
//!
//! This rule detects alternating read/write operations on a stream without
//! an intervening fseek(), fflush(), fsetpos(), or rewind() call.
//!
//! The C Standard requires that input and output operations on update streams
//! be separated by a positioning or flush function, otherwise undefined behavior occurs.
//!
//! Each call is tied to the stream it operates on, and the alternation is
//! tracked per stream: reading one stream and writing another (a copy loop
//! through one buffer) is not alternation. A positioning or flush call
//! resets only its own stream, and `fflush(NULL)` resets every stream.
//!
//! VIOLATIONS:
//! - fwrite() followed directly by fread() without fseek/fflush/fsetpos/rewind
//! - fread() followed directly by fwrite() without fseek/fflush/fsetpos/rewind
//! - fprintf() followed by fscanf() without intervening call
//!
//! COMPLIANT:
//! - fwrite() then fseek() then fread()
//! - fwrite() then fflush() then fread()
//! - fread() then fsetpos() then fwrite()
//! - fread() on one stream then fwrite() on another

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{get_node_text, resolve_identifier_declarator};
use lang_parsing_substrate::query;
use std::collections::BTreeMap;
use tree_sitter::Node;

pub struct Fio39C;

// Functions that perform output
const OUTPUT_FUNCTIONS: &[&str] = &[
    "fwrite", "fprintf", "vfprintf", "fputs", "fputc", "putc", "fputwc", "putwc", "fputws",
];

// Functions that perform input
const INPUT_FUNCTIONS: &[&str] = &[
    "fread", "fscanf", "vfscanf", "fgets", "fgetc", "getc", "fgetwc", "getwc", "fgetws", "ungetc",
    "ungetwc",
];

// The calls above and below that take their `FILE *` as the LAST argument;
// the rest take it first (`fprintf(fp, ...)`, `fgetc(fp)`, `fseek(fp, ...)`).
// Reading the first argument of `fread(buf, 1, n, fp)` would key the call on
// the buffer, not the stream.
const STREAM_LAST_FUNCTIONS: &[&str] = &[
    "fread", "fwrite", "fgets", "fputs", "fputc", "putc", "fputwc", "putwc", "fputws", "fgetws",
    "ungetc", "ungetwc",
];

// Functions that reset the stream state (positioning/flush)
const POSITIONING_FUNCTIONS: &[&str] = &["fseek", "fflush", "fsetpos", "rewind"];

impl CertRule for Fio39C {
    fn rule_id(&self) -> &'static str {
        "FIO39-C"
    }

    fn description(&self) -> &'static str {
        "Do not alternately input and output from a stream without an intervening flush or positioning call"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "FIO39-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_function_body(node, source, violations);
    }
}

impl Fio39C {
    fn check_function_body(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Find function definitions and check their bodies
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(body) = func.child_by_field_name("body") {
                self.analyze_compound_statement(&body, source, violations);
            }
        }
    }

    fn analyze_compound_statement(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        #[derive(Clone, Copy, PartialEq)]
        enum IoOp {
            Input,
            Output,
        }

        // The last input or output call on each stream since that stream's
        // last positioning or flush call, keyed by `stream_key`.
        let mut last_op: BTreeMap<String, (IoOp, String)> = BTreeMap::new();

        for (call, func_name) in self.collect_calls_in_order(node, source) {
            let Some(stream) = self.stream_argument(&call, &func_name) else {
                continue;
            };
            let stream_text = get_node_text(&stream, source).to_string();
            if POSITIONING_FUNCTIONS.contains(&func_name.as_str()) {
                if func_name == "fflush" && matches!(stream_text.trim(), "NULL" | "0") {
                    last_op.clear();
                } else {
                    last_op.remove(&stream_key(&stream, source));
                }
                continue;
            }
            let op = if OUTPUT_FUNCTIONS.contains(&func_name.as_str()) {
                IoOp::Output
            } else if INPUT_FUNCTIONS.contains(&func_name.as_str()) {
                IoOp::Input
            } else {
                continue;
            };
            let key = stream_key(&stream, source);
            if let Some((previous, previous_name)) = last_op.get(&key) {
                if *previous != op {
                    let (what, before) = match op {
                        IoOp::Output => ("Output", "input"),
                        IoOp::Input => ("Input", "output"),
                    };
                    let pos = call.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Low,
                        message: format!(
                            "{what} function '{func_name}' called on stream '{stream_text}' after {before} function '{previous_name}' without intervening fseek/fflush/fsetpos/rewind"
                        ),
                        file_path: String::new(),
                        line: pos.row + 1,
                        column: pos.column + 1,
                        suggestion: Some(
                            "Add fseek(), fflush(), fsetpos(), or rewind() on this stream between input and output operations".to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
            last_op.insert(key, (op, func_name));
        }
    }

    /// The stream argument of a stdio call this rule tracks, or `None` for
    /// any other call.
    fn stream_argument<'a>(&self, call: &Node<'a>, func_name: &str) -> Option<Node<'a>> {
        if !OUTPUT_FUNCTIONS.contains(&func_name)
            && !INPUT_FUNCTIONS.contains(&func_name)
            && !POSITIONING_FUNCTIONS.contains(&func_name)
        {
            return None;
        }
        let arguments = call.child_by_field_name("arguments")?;
        let mut cursor = arguments.walk();
        let args: Vec<Node> = arguments
            .named_children(&mut cursor)
            .filter(|c| c.kind() != "comment")
            .collect();
        if STREAM_LAST_FUNCTIONS.contains(&func_name) {
            args.last().copied()
        } else {
            args.first().copied()
        }
    }

    /// Every call in `node`, in source order, with its callee's name.
    fn collect_calls_in_order<'a>(&self, node: &Node<'a>, source: &str) -> Vec<(Node<'a>, String)> {
        let mut calls: Vec<(Node<'a>, String)> =
            query::find_descendants_of_kind(*node, "call_expression")
                .into_iter()
                .filter_map(|call| {
                    let function = call.child_by_field_name("function")?;
                    Some((call, get_node_text(&function, source).to_string()))
                })
                .collect();
        calls.sort_by_key(|(call, _)| call.start_byte());
        calls
    }
}

/// What a stream argument names, so two calls on the same stream share a
/// key: an identifier by the declaration it resolves to (ADR-0006: a name
/// shadowed in an inner block is another stream), anything else (`ctx->fp`,
/// `files[i]`) by its text, parentheses dropped.
fn stream_key(stream: &Node, source: &str) -> String {
    let mut expr = *stream;
    while expr.kind() == "parenthesized_expression" {
        match expr.named_child(0) {
            Some(inner) => expr = inner,
            None => break,
        }
    }
    let text = get_node_text(&expr, source);
    if expr.kind() == "identifier" {
        if let Some((_, declarator)) = resolve_identifier_declarator(&expr, text, source) {
            return format!("decl@{}", declarator.start_byte());
        }
    }
    format!("text:{text}")
}
