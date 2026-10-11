// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

// FIO46-C: Do not access a closed file
// https://wiki.sei.cmu.edu/confluence/display/c/FIO46-C
//
// After `fclose(s)` the value of `s` is indeterminate (C11 7.21.3p4), so on
// any path from the close that does not first assign `s` again, passing `s`
// to a function, `fclose` included, or reading it is undefined. A close of a
// standard stream also closes it for the functions that use it without
// naming it: `printf` and `puts` write `stdout`, `scanf` and `getchar` read
// `stdin`, `perror` writes `stderr`.
//
// The paths are the function's control-flow graph: a close on a branch that
// returns reaches nothing after the branch, and a call to a noreturn
// function ends its path.

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::{build_function_cfg_with_constants_and_noreturn, BlockId, FunctionCfg};
use crate::analyze::const_eval::MacroConstantMap;
use crate::analyze::context::ProjectContext;
use crate::analyze::dataflow::find_node_at_range;
use crate::analyze::noreturn::{
    called_function_name, library_names_redefined_among, noreturn_names_for_file, ByNoreturnTrust,
};
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::{get_node_text, stream_key};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::sync::Arc;
use tree_sitter::Node;

/// Functions that write `stdout` without naming it: C11 7.21.6.3 `printf`,
/// 7.21.6.10 `vprintf`, 7.21.7.8 `putchar`, 7.21.7.9 `puts`, and their wide
/// forms, 7.29.2.11 `wprintf`, 7.29.2.9 `vwprintf`, 7.29.3.9 `putwchar`.
/// `putc` names its stream and is not one of them.
const STDOUT_IMPLICIT: &[&str] = &[
    "printf", "vprintf", "putchar", "puts", "wprintf", "vwprintf", "putwchar",
];

/// Functions that read `stdin` without naming it: C11 7.21.6.4 `scanf`,
/// 7.21.6.12 `vscanf`, 7.21.7.6 `getchar`, the wide forms 7.29.2.12
/// `wscanf`, 7.29.2.10 `vwscanf`, 7.29.3.7 `getwchar`, Annex K's K.3.5.3.4
/// `scanf_s`, K.3.5.3.11 `vscanf_s` and K.3.5.4.1 `gets_s`, and C99's `gets`.
const STDIN_IMPLICIT: &[&str] = &[
    "scanf", "vscanf", "getchar", "wscanf", "vwscanf", "getwchar", "scanf_s", "vscanf_s", "gets_s",
    "gets",
];

/// Functions that write `stderr` without naming it: C11 7.21.10.4 `perror`.
const STDERR_IMPLICIT: &[&str] = &["perror"];

/// The streams that may be closed at a program point, by [`stream_key`], each
/// with the earliest close that reaches it.
type Closed = BTreeMap<String, ClosedBy>;

/// A close of a stream: where the `fclose` call is, and the stream as it was
/// spelled there. Ordered by position, so the earliest close sorts first.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ClosedBy {
    line: usize,
    byte: usize,
    spelling: String,
}

pub struct Fio46C {
    /// The prescan's cross-file noreturn functions, under each noreturn
    /// setting.
    noreturn_functions: RefCell<ByNoreturnTrust<Arc<HashSet<String>>>>,
    /// The run's settings, which pick the noreturn set.
    settings: RefCell<Arc<AnalysisSettings>>,
}

impl Fio46C {
    pub fn new() -> Self {
        Self {
            noreturn_functions: RefCell::default(),
            settings: RefCell::default(),
        }
    }
}

impl Default for Fio46C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Fio46C {
    fn rule_id(&self) -> &'static str {
        "FIO46-C"
    }

    fn description(&self) -> &'static str {
        "Do not access a closed file"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "FIO46-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.noreturn_functions.borrow_mut() = context.noreturn_functions.clone();
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        *self.settings.borrow_mut() = Arc::clone(settings);
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // A file that defines its own `fclose` calls that, not the library's.
        if library_names_redefined_among(node, source, |name| name == "fclose").contains("fclose") {
            return;
        }
        let functions = query::find_descendants_of_kind(*node, "function_definition");
        if !functions.iter().any(|f| closes_a_stream(f, source)) {
            return;
        }
        let settings = Arc::clone(&self.settings.borrow());
        let noreturn = noreturn_names_for_file(
            self.noreturn_functions.borrow().get(&settings),
            node,
            source,
            &settings,
        );
        for func in functions {
            if closes_a_stream(&func, source) {
                self.analyze_function(&func, source, &noreturn, violations);
            }
        }
    }
}

/// Whether `func` spells a call to `fclose`: the cheap test before a CFG.
fn closes_a_stream(func: &Node, source: &str) -> bool {
    query::find_descendants_of_kind(*func, "call_expression")
        .iter()
        .any(|call| callee_spelling(call, source) == Some("fclose"))
}

/// The callee as written, parentheses dropped, without resolving it.
fn callee_spelling<'a>(call: &Node, source: &'a str) -> Option<&'a str> {
    let function = call.child_by_field_name("function")?;
    Some(
        get_node_text(&function, source)
            .trim_matches(|c: char| c == '(' || c == ')' || c.is_whitespace()),
    )
}

/// What one walk over a block's statements found.
enum Finding {
    /// `fclose` of a stream that may already be closed.
    /// `same_call` when the earlier close is this call, on an earlier pass
    /// through a loop.
    DoubleClose {
        stream: String,
        closed_at: usize,
        same_call: bool,
    },
    /// A stream that may be closed, passed to a function or read.
    Use {
        stream: String,
        closed_at: usize,
        callee: Option<String>,
    },
    /// A function that uses a standard stream implicitly, after it may have
    /// been closed.
    Implicit {
        function: String,
        stream: &'static str,
        closed_at: usize,
    },
}

impl Fio46C {
    fn analyze_function(
        &self,
        func: &Node,
        source: &str,
        noreturn: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(cfg) = build_function_cfg_with_constants_and_noreturn(
            func,
            source,
            &MacroConstantMap::new(),
            noreturn,
        ) else {
            return;
        };
        // Streams the function closes, by spelling: an identifier spelled
        // otherwise is never resolved.
        let spellings: BTreeSet<String> = query::find_descendants_of_kind(*func, "call_expression")
            .iter()
            .filter(|call| callee_spelling(call, source) == Some("fclose"))
            .filter_map(|call| first_argument(call))
            .map(|arg| stream_spelling(&arg, source))
            .collect();
        let walker = Walker {
            func: *func,
            source,
            spellings: &spellings,
        };

        let entry_state = solve(&cfg, &walker);
        let mut seen = HashSet::new();
        for block in &cfg.blocks {
            let Some(state) = entry_state.get(&block.id) else {
                continue;
            };
            let mut state = state.clone();
            let mut findings = Vec::new();
            walker.block(&cfg, block.id, &mut state, Some(&mut findings));
            for (node, finding) in findings {
                if seen.insert((node.start_byte(), node.end_byte())) {
                    violations.push(self.violation(&node, finding));
                }
            }
        }
    }

    fn violation(&self, node: &Node, finding: Finding) -> RuleViolation {
        let (message, suggestion) = match finding {
            Finding::DoubleClose {
                stream,
                closed_at,
                same_call,
            } => (
                if same_call {
                    format!(
                        "Stream '{stream}' may already be closed by this fclose() on an earlier pass through the loop. Closing a closed stream is undefined behavior."
                    )
                } else {
                    format!(
                        "Stream '{stream}' may already be closed by fclose() at line {closed_at}. Closing a closed stream is undefined behavior."
                    )
                },
                "Close each stream once, or assign it again (NULL, or a new open) after the first fclose().",
            ),
            Finding::Use {
                stream,
                closed_at,
                callee: Some(callee),
            } => (
                format!(
                    "Function '{callee}' uses file stream '{stream}' after it may have been closed with fclose() at line {closed_at}. Accessing a closed file stream is undefined behavior."
                ),
                "Do not access file streams after closing them.",
            ),
            Finding::Use {
                stream,
                closed_at,
                callee: None,
            } => (
                format!(
                    "File stream '{stream}' is read after it may have been closed with fclose() at line {closed_at}. Its value is indeterminate once closed."
                ),
                "Do not access file streams after closing them.",
            ),
            Finding::Implicit {
                function,
                stream,
                closed_at,
            } => (
                format!(
                    "Function '{function}' uses {stream} after it may have been closed with fclose() at line {closed_at}. Accessing a closed file stream is undefined behavior."
                ),
                "Do not use functions that access a standard stream after closing it, or name another stream explicitly.",
            ),
        };
        let position = node.start_position();
        RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            line: position.row + 1,
            column: position.column + 1,
            file_path: String::new(),
            message,
            suggestion: Some(suggestion.to_string()),
            requires_manual_review: None,
        }
    }
}

/// The closed state at each reachable block's entry: a forward may-analysis
/// whose merge is union, so a stream closed on any path into a block may be
/// closed there. A block is walked again only when its entry state gains a
/// stream or an earlier close of one, and both only move one way, so this
/// ends.
fn solve(cfg: &FunctionCfg, walker: &Walker) -> BTreeMap<BlockId, Closed> {
    let mut entry: BTreeMap<BlockId, Closed> = BTreeMap::new();
    entry.insert(cfg.entry, Closed::new());
    let mut work = VecDeque::from([cfg.entry]);
    while let Some(id) = work.pop_front() {
        let mut state = entry[&id].clone();
        walker.block(cfg, id, &mut state, None);
        for (succ, _) in cfg.successors(id) {
            let first_visit = !entry.contains_key(&succ);
            let into = entry.entry(succ).or_default();
            let mut grew = false;
            for (stream, closed) in &state {
                match into.get_mut(stream) {
                    Some(have) if *have <= *closed => {}
                    // An earlier close reaches the block: the state is the
                    // same streams, but its messages name another line.
                    Some(have) => {
                        *have = closed.clone();
                        grew = true;
                    }
                    None => {
                        into.insert(stream.clone(), closed.clone());
                        grew = true;
                    }
                }
            }
            if (first_visit || grew) && !work.contains(&succ) {
                work.push_back(succ);
            }
        }
    }
    entry
}

/// The stream an argument names, as it is spelled: what a `fclose` argument
/// is filtered by before anything is resolved.
fn stream_spelling(arg: &Node, source: &str) -> String {
    let mut expr = *arg;
    while expr.kind() == "parenthesized_expression" {
        match expr.named_child(0) {
            Some(inner) => expr = inner,
            None => break,
        }
    }
    get_node_text(&expr, source).to_string()
}

fn first_argument<'a>(call: &Node<'a>) -> Option<Node<'a>> {
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let first = args.named_children(&mut cursor).next();
    first
}

/// Walks statements in evaluation order, updating the closed state and,
/// when asked, recording what it finds.
struct Walker<'s, 't> {
    func: Node<'t>,
    source: &'s str,
    /// The spellings of the streams the function closes.
    spellings: &'s BTreeSet<String>,
}

impl<'t> Walker<'_, 't> {
    fn block(
        &self,
        cfg: &FunctionCfg,
        id: BlockId,
        state: &mut Closed,
        mut findings: Option<&mut Vec<(Node<'t>, Finding)>>,
    ) {
        let Some(block) = cfg.get_block(id) else {
            return;
        };
        for &(start, end) in &block.statements {
            if let Some(stmt) = find_node_at_range(&self.func, start, end) {
                self.expr(&stmt, state, &mut findings);
            }
        }
    }

    fn tracked(&self, node: &Node) -> bool {
        self.spellings.contains(&stream_spelling(node, self.source))
    }

    fn expr(
        &self,
        node: &Node<'t>,
        state: &mut Closed,
        findings: &mut Option<&mut Vec<(Node<'t>, Finding)>>,
    ) {
        match node.kind() {
            "sizeof_expression" | "alignof_expression" | "offsetof_expression" => {}
            "function_definition" | "compound_statement" => {}
            "call_expression" => self.call(node, state, findings),
            "assignment_expression" => {
                if let Some(right) = node.child_by_field_name("right") {
                    self.expr(&right, state, findings);
                }
                let Some(left) = node.child_by_field_name("left") else {
                    return;
                };
                let plain = node
                    .child_by_field_name("operator")
                    .is_some_and(|op| get_node_text(&op, self.source) == "=");
                if plain && self.tracked(&left) {
                    state.remove(&stream_key(&left, self.source));
                } else {
                    self.expr(&left, state, findings);
                }
            }
            "init_declarator" => {
                if let Some(value) = node.child_by_field_name("value") {
                    self.expr(&value, state, findings);
                }
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    self.declared(&declarator, state);
                }
            }
            "declaration" => {
                let mut cursor = node.walk();
                for declarator in node.children_by_field_name("declarator", &mut cursor) {
                    if declarator.kind() == "init_declarator" {
                        self.expr(&declarator, state, findings);
                    } else {
                        self.declared(&declarator, state);
                    }
                }
            }
            "pointer_expression"
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|op| get_node_text(&op, self.source) == "&") =>
            {
                // `&fp` lets whatever receives it store a new stream there
                // (`fopen_s(&fp, ...)`): the old one is no longer `fp`'s.
                if let Some(operand) = node.child_by_field_name("argument") {
                    if self.tracked(&operand) {
                        state.remove(&stream_key(&operand, self.source));
                    } else {
                        self.expr(&operand, state, findings);
                    }
                }
            }
            "identifier" | "field_expression" | "subscript_expression" if self.tracked(node) => {
                self.read(node, None, state, findings);
            }
            _ => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    self.expr(&child, state, findings);
                }
            }
        }
    }

    /// A declaration starts a new object: whatever its name held is gone.
    fn declared(&self, declarator: &Node, state: &mut Closed) {
        for ident in query::find_descendants_of_kind(*declarator, "identifier") {
            if self.tracked(&ident) {
                state.remove(&stream_key(&ident, self.source));
            }
        }
        if declarator.kind() == "identifier" && self.tracked(declarator) {
            state.remove(&stream_key(declarator, self.source));
        }
    }

    fn read(
        &self,
        node: &Node<'t>,
        callee: Option<&str>,
        state: &Closed,
        findings: &mut Option<&mut Vec<(Node<'t>, Finding)>>,
    ) {
        let key = stream_key(node, self.source);
        if let (Some(closed), Some(findings)) = (state.get(&key), findings.as_deref_mut()) {
            findings.push((
                *node,
                Finding::Use {
                    stream: stream_spelling(node, self.source),
                    closed_at: closed.line,
                    callee: callee.map(str::to_string),
                },
            ));
        }
    }

    fn call(
        &self,
        call: &Node<'t>,
        state: &mut Closed,
        findings: &mut Option<&mut Vec<(Node<'t>, Finding)>>,
    ) {
        let name = called_function_name(call, self.source);
        if name.as_deref() == Some("fclose") {
            if let Some(stream) = first_argument(call) {
                let key = stream_key(&stream, self.source);
                if let (Some(closed), Some(findings)) = (state.get(&key), findings.as_deref_mut()) {
                    findings.push((
                        *call,
                        Finding::DoubleClose {
                            stream: stream_spelling(&stream, self.source),
                            closed_at: closed.line,
                            same_call: closed.byte == call.start_byte(),
                        },
                    ));
                }
                state.insert(
                    key,
                    ClosedBy {
                        line: call.start_position().row + 1,
                        byte: call.start_byte(),
                        spelling: stream_spelling(&stream, self.source),
                    },
                );
            }
            return;
        }
        if let Some(function) = call.child_by_field_name("function") {
            if name.is_none() {
                self.expr(&function, state, findings);
            }
        }
        if let Some(args) = call.child_by_field_name("arguments") {
            let mut cursor = args.walk();
            for arg in args.named_children(&mut cursor) {
                let mut inner = arg;
                while inner.kind() == "parenthesized_expression" {
                    match inner.named_child(0) {
                        Some(i) => inner = i,
                        None => break,
                    }
                }
                if matches!(
                    inner.kind(),
                    "identifier" | "field_expression" | "subscript_expression"
                ) && self.tracked(&inner)
                {
                    let callee = name.clone().unwrap_or_else(|| {
                        call.child_by_field_name("function")
                            .map(|f| get_node_text(&f, self.source).to_string())
                            .unwrap_or_default()
                    });
                    self.read(&inner, Some(&callee), state, findings);
                } else {
                    self.expr(&arg, state, findings);
                }
            }
        }
        let Some(name) = name else {
            return;
        };
        let stream = if STDOUT_IMPLICIT.contains(&name.as_str()) {
            "stdout"
        } else if STDIN_IMPLICIT.contains(&name.as_str()) {
            "stdin"
        } else if STDERR_IMPLICIT.contains(&name.as_str()) {
            "stderr"
        } else {
            return;
        };
        // The standard streams are macros (C11 7.21.1p3) whose declarations
        // a scan does not usually see, so a close of one is matched by the
        // name the standard gives it.
        let closed = state
            .values()
            .filter(|closed| closed.spelling == stream)
            .map(|closed| closed.line)
            .min();
        if let (Some(closed_at), Some(findings)) = (closed, findings.as_deref_mut()) {
            findings.push((
                *call,
                Finding::Implicit {
                    function: name,
                    stream,
                    closed_at,
                },
            ));
        }
    }
}
