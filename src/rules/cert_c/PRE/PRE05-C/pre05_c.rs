// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! PRE05-C: Understand macro replacement when concatenating tokens or performing stringification
//!
//! This rule requires understanding how the C preprocessor handles the `##` (token
//! concatenation) and `#` (stringification) operators. When these operators are used
//! directly on macro parameters, the parameters are NOT expanded before the operation.
//! To get proper macro expansion, an additional level of indirection is required.
//!
//! ## Examples:
//!
//! **Non-compliant (single-level macro with ##):**
//! ```c
//! #define JOIN(x, y) x ## y
//! // Problem: x and y are not expanded before concatenation
//! ```
//!
//! **Non-compliant (single-level macro with #):**
//! ```c
//! #define str(s) #s
//! #define foo 4
//! str(foo)  // Produces "foo", not "4"
//! ```
//!
//! **Compliant (two-level indirection for ##):**
//! ```c
//! #define JOIN(x, y) JOIN_AGAIN(x, y)
//! #define JOIN_AGAIN(x, y) x ## y
//! // Now x and y are expanded before concatenation
//! ```
//!
//! **Compliant (two-level indirection for #):**
//! ```c
//! #define xstr(s) str(s)
//! #define str(s) #s
//! #define foo 4
//! xstr(foo)  // Produces "4"
//! ```
//!
//! ## Detection strategy
//!
//! The defect is at the invocation, not the definition: `#define str(s) #s`
//! is harmless until something passes it a macro name. So the rule reports
//! an invocation of a function-like macro that passes, to a parameter the
//! macro stringizes or pastes, an argument whose first token is a macro
//! defined at that point (or a predefined one such as `__LINE__`). An
//! argument that is the enclosing `#define`'s own parameter was already
//! expanded when it was substituted, which is why the two-level form
//! (`xstr`, `JOIN_AGAIN`) is compliant. Which parameters are operands comes
//! from every branch's definition (`macro_expand::collect_macro_operand_params`),
//! this file's and every scanned file's.
//!
//! Only a parameter used exclusively as a `#`/`##` operand counts. One the
//! same definition also uses plainly is fully expanded where it is used, and
//! its `#` only prints the source text: `assert(expr)` evaluating `expr` and
//! reporting `#expr`, or a `case x: return #x;` table.
//!
//! A name known only as a function-like macro is not expanded unless the
//! next token is `(` (C11 6.10.3p10), so `STR(min)` with a function-like
//! `min` stringizes "min" either way and is not reported; `STR(min(1, 2))`
//! is.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::macro_expand::{
    collect_macro_operand_params, merge_operand_params, OperandParams,
};
use crate::manifest::Severity;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

/// Macros every translation unit has without a `#define` (C11 6.10.8), plus
/// the common `__COUNTER__` extension.
const PREDEFINED_MACROS: &[&str] = &[
    "__LINE__",
    "__FILE__",
    "__DATE__",
    "__TIME__",
    "__STDC__",
    "__STDC_VERSION__",
    "__STDC_HOSTED__",
    "__COUNTER__",
];

pub struct Pre05C {
    /// `ProjectContext::macro_operand_params`: a stringizing or pasting
    /// macro is usually defined in a header.
    project_operand_params: RefCell<Arc<HashMap<String, OperandParams>>>,
    /// `ProjectContext::defined_macro_names`: every `#define` name in any
    /// scanned file.
    project_macro_names: RefCell<Arc<HashSet<String>>>,
    /// `ProjectContext::function_macro_names`: every function-like
    /// `#define` name in any scanned file.
    project_function_macros: RefCell<Arc<HashSet<String>>>,
    /// Names some scanned file defines object-like, as far as the project
    /// tables say: `macro_constants` and `macro_aliases`.
    project_object_macros: RefCell<HashSet<String>>,
}

impl Pre05C {
    pub fn new() -> Self {
        Self {
            project_operand_params: RefCell::new(Arc::new(HashMap::new())),
            project_macro_names: RefCell::new(Arc::new(HashSet::new())),
            project_function_macros: RefCell::new(Arc::new(HashSet::new())),
            project_object_macros: RefCell::new(HashSet::new()),
        }
    }
}

impl Default for Pre05C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Pre05C {
    fn reads_header_facts(&self) -> bool {
        true
    }

    fn rule_id(&self) -> &'static str {
        "PRE05-C"
    }

    fn description(&self) -> &'static str {
        "Understand macro replacement when concatenating tokens or performing stringification"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "PRE05-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_operand_params.borrow_mut() = context.macro_operand_params.clone();
        *self.project_macro_names.borrow_mut() = context.defined_macro_names.clone();
        *self.project_function_macros.borrow_mut() = context.function_macro_names.clone();
        *self.project_object_macros.borrow_mut() = context
            .macro_constants
            .keys()
            .chain(context.macro_aliases.keys())
            .cloned()
            .collect();
    }

    fn check(&self, _node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut operand_params = HashMap::clone(&self.project_operand_params.borrow());
        let mut local = HashMap::new();
        collect_macro_operand_params(source, &mut local);
        for (name, params) in local {
            merge_operand_params(&mut operand_params, name, params);
        }
        if operand_params.is_empty() {
            return Vec::new();
        }
        let directives = Directive::scan(source);
        let project_names = self.project_macro_names.borrow();
        let mut violations = Vec::new();
        for call in find_invocations(source, &operand_params, &directives) {
            let params = &operand_params[&call.name];
            let enclosing = directives.iter().find(|d| d.range.contains(&call.offset));
            for (index, arg) in call.args.iter().enumerate() {
                if !params.covers_argument(index) {
                    continue;
                }
                let Some(first) = first_identifier(arg) else {
                    continue;
                };
                // The enclosing #define's own parameter was fully expanded
                // before it was substituted: the compliant two-level form.
                if enclosing.is_some_and(|d| d.params.iter().any(|p| p == first)) {
                    continue;
                }
                let is_macro = PREDEFINED_MACROS.contains(&first)
                    || project_names.contains(first)
                    || defined_in_file_at(&directives, first, call.offset, enclosing.is_some());
                if !is_macro {
                    continue;
                }
                // A function-like macro name not followed by `(` is not
                // expanded, so # and ## see the same token either way.
                let followed_by_call = arg.trim_start()[first.len()..]
                    .trim_start()
                    .starts_with('(');
                if !followed_by_call && self.only_function_like(first, &directives) {
                    continue;
                }
                let (line, column) = line_column(source, call.offset);
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Low,
                    message: format!(
                        "'{first}' is a macro, but '{}' applies # or ## to the parameter it is \
                         passed to, so it is stringized or pasted as written instead of being \
                         expanded first",
                        call.name
                    ),
                    file_path: String::new(),
                    line,
                    column,
                    suggestion: Some(format!(
                        "Pass it through a second macro level that does not use # or ##, \
                         e.g. #define x{0}(...) {0}(__VA_ARGS__), so the argument is expanded \
                         before '{0}' stringizes or pastes it",
                        call.name
                    )),
                    ..Default::default()
                });
            }
        }
        violations
    }
}

impl Pre05C {
    /// Whether every definition of `name` in sight is function-like: this
    /// file's `#define`s of it, or, when it has none, the project's tables.
    /// A name any definition makes object-like expands on its own.
    fn only_function_like(&self, name: &str, directives: &[Directive]) -> bool {
        if PREDEFINED_MACROS.contains(&name) || self.project_object_macros.borrow().contains(name) {
            return false;
        }
        let mut local = directives
            .iter()
            .filter(|d| d.kind == DirectiveKind::Define && d.name == name)
            .peekable();
        if local.peek().is_some() {
            return local.all(|d| d.function_like);
        }
        self.project_function_macros.borrow().contains(name)
    }
}

/// One preprocessor directive (continuation lines joined) and, for a
/// `#define`/`#undef`, the name it defines or removes.
struct Directive {
    range: std::ops::Range<usize>,
    kind: DirectiveKind,
    name: String,
    /// The parameters of a function-like `#define`.
    params: Vec<String>,
    /// A `#define` whose name is followed directly by `(`.
    function_like: bool,
    /// Byte offset of the name in a `#define`/`#undef`.
    name_offset: usize,
}

#[derive(PartialEq)]
enum DirectiveKind {
    Define,
    Undef,
    Other,
}

impl Directive {
    fn scan(source: &str) -> Vec<Directive> {
        let mut out = Vec::new();
        let mut offset = 0;
        let mut lines = source.split_inclusive('\n').peekable();
        while let Some(first) = lines.next() {
            let start = offset;
            offset += first.len();
            let mut text = first.to_string();
            while text.trim_end_matches(['\n', '\r']).ends_with('\\') {
                let Some(next) = lines.next() else { break };
                offset += next.len();
                text.push_str(next);
            }
            let trimmed = text.trim_start();
            let Some(rest) = trimmed.strip_prefix('#') else {
                continue;
            };
            let rest_trimmed = rest.trim_start();
            let (kind, after) = if let Some(a) = rest_trimmed.strip_prefix("define") {
                (DirectiveKind::Define, a)
            } else if let Some(a) = rest_trimmed.strip_prefix("undef") {
                (DirectiveKind::Undef, a)
            } else {
                (DirectiveKind::Other, "")
            };
            let mut name = String::new();
            let mut params = Vec::new();
            let mut name_offset = start;
            let mut function_like = false;
            if kind != DirectiveKind::Other && after.starts_with(char::is_whitespace) {
                let after_ws = after.trim_start();
                name = after_ws
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                name_offset = start + (text.len() - after_ws.len());
                let tail = &after_ws[name.len()..];
                if kind == DirectiveKind::Define {
                    function_like = tail.starts_with('(');
                    if let Some(list) = tail.strip_prefix('(') {
                        if let Some(close) = list.find(')') {
                            params = list[..close]
                                .split(',')
                                .map(|p| p.trim().trim_end_matches("...").trim().to_string())
                                .filter(|p| !p.is_empty())
                                .collect();
                        }
                    }
                }
            }
            out.push(Directive {
                range: start..offset,
                kind,
                name,
                params,
                function_like,
                name_offset,
            });
        }
        out
    }
}

/// Whether this file `#define`s `name` in effect at `offset`: its last
/// `#define`/`#undef` before `offset` is a `#define`. Inside another
/// macro's replacement list, "that point" is wherever the enclosing macro is
/// expanded, which the text cannot say, so any `#define` of `name` counts.
fn defined_in_file_at(
    directives: &[Directive],
    name: &str,
    offset: usize,
    in_define: bool,
) -> bool {
    let mut defined = false;
    for d in directives.iter().filter(|d| d.name == name) {
        if in_define {
            if d.kind == DirectiveKind::Define {
                return true;
            }
            continue;
        }
        if d.range.start >= offset {
            break;
        }
        defined = d.kind == DirectiveKind::Define;
    }
    defined
}

/// One invocation of a macro in `operand_params`: its name, the byte offset
/// of that name, and its arguments as written.
struct Invocation {
    name: String,
    offset: usize,
    args: Vec<String>,
}

/// Every invocation of a macro in `operand_params`, in code and in other
/// macros' replacement lists, skipping comments, string and character
/// literals, and the name in a macro's own `#define`.
fn find_invocations(
    source: &str,
    operand_params: &HashMap<String, OperandParams>,
    directives: &[Directive],
) -> Vec<Invocation> {
    let defining: HashSet<usize> = directives
        .iter()
        .filter(|d| d.kind != DirectiveKind::Other)
        .map(|d| d.name_offset)
        .collect();
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else if c == b'"' || c == b'\'' {
            i = skip_literal(bytes, i);
        } else if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let name = &source[start..i];
            if !operand_params.contains_key(name) || defining.contains(&start) {
                continue;
            }
            let mut j = i;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if bytes.get(j) != Some(&b'(') {
                continue;
            }
            // Arguments may hold further invocations, so scanning resumes
            // inside them rather than past the closing parenthesis.
            if let Some(args) = split_arguments(source, j) {
                out.push(Invocation {
                    name: name.to_string(),
                    offset: start,
                    args,
                });
            }
        } else {
            i += 1;
        }
    }
    out
}

/// The index just past the string or character literal starting at `start`.
fn skip_literal(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let mut i = start + 1;
    while i < bytes.len() && bytes[i] != quote && bytes[i] != b'\n' {
        if bytes[i] == b'\\' {
            i += 1;
        }
        i += 1;
    }
    i + 1
}

/// The arguments of the parenthesized list opening at `open`, split at
/// top-level commas. `None` if unclosed.
fn split_arguments(source: &str, open: usize) -> Option<Vec<String>> {
    let bytes = source.as_bytes();
    let mut args = Vec::new();
    let mut depth = 0;
    let mut arg_start = open + 1;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' => {
                i = skip_literal(bytes, i);
                continue;
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    let last = source[arg_start..i].trim();
                    if !last.is_empty() || !args.is_empty() {
                        args.push(last.to_string());
                    }
                    return Some(args);
                }
            }
            b',' if depth == 1 => {
                args.push(source[arg_start..i].trim().to_string());
                arg_start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The argument's first token when it is an identifier.
fn first_identifier(arg: &str) -> Option<&str> {
    let arg = arg.trim_start();
    let len = arg
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(arg.len());
    let first = &arg[..len];
    (!first.is_empty() && !first.starts_with(|c: char| c.is_ascii_digit())).then_some(first)
}

/// 1-based line and column of byte `offset`.
fn line_column(source: &str, offset: usize) -> (usize, usize) {
    let before = &source[..offset];
    let line = before.matches('\n').count() + 1;
    let column = offset - before.rfind('\n').map_or(0, |n| n + 1) + 1;
    (line, column)
}
