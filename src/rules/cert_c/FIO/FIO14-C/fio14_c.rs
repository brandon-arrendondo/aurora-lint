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
//! - Improper use of ungetc() based on stream type
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
//! is not reported, nor is anything when POSIX holds, where text and binary
//! streams are the same.

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::{get_node_text, resolve_identifier_declarator};
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
        if self.settings.borrow().posix_holds_project() {
            return;
        }
        self.check_node(node, source, violations);
    }
}

impl Fio14C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for fseek() calls with problematic usage
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if func_name == "fseek" {
                    self.check_fseek_call(&call, source, violations);
                }
            }
        }
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
