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
//
// CERT generalizes the rule to other file representations. Where POSIX holds,
// a second `close(fd)` on a path from a first, with `fd` not assigned between,
// is reported too. That is not undefined: POSIX gives it `EBADF`, and the harm
// is that the number may by then name a file another open returned. Nothing
// else is read about a descriptor, since an `int` stays valid after its close.

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::{
    build_function_cfg_with_constants_and_noreturn, BlockId, CfgEdge, FunctionCfg,
};
use crate::analyze::const_eval::{
    collect_macro_alias_alternatives, resolve_macro_alias_where, MacroConstantMap,
};
use crate::analyze::context::ProjectContext;
use crate::analyze::dataflow::find_node_at_range;
use crate::analyze::noreturn::{
    called_function_name, library_function_replaced, library_names_redefined_among,
    noreturn_names_for_file, ByNoreturnTrust,
};
use crate::analyze::preproc_arms::PreprocArms;
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::{get_node_text, resolve_identifier_declarator, stream_key};
use crate::utility::cert_c::std_functions::is_iso_c_or_posix_function;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
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
    /// The prescan's macro tables: a project macro named `fclose` replaces
    /// the library function in the files that can see it.
    project: RefCell<Option<ProjectContext>>,
    /// The file being checked, for the headers it includes.
    file_path: RefCell<Option<PathBuf>>,
}

impl Fio46C {
    pub fn new() -> Self {
        Self {
            noreturn_functions: RefCell::default(),
            settings: RefCell::default(),
            project: RefCell::default(),
            file_path: RefCell::default(),
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
        *self.project.borrow_mut() = Some(context.clone());
    }

    fn set_file_path(&self, path: &std::path::Path) {
        *self.file_path.borrow_mut() = Some(path.to_path_buf());
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        *self.settings.borrow_mut() = Arc::clone(settings);
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.scan_streams(node, source, violations);
        if self.settings.borrow().posix_holds_project() {
            self.scan_descriptors(node, source, violations);
        }
    }
}

impl Fio46C {
    fn scan_streams(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let functions = query::find_descendants_of_kind(*node, "function_definition");
        if !functions.iter().any(|f| closes_a_stream(f, source)) {
            return;
        }
        // A file whose `fclose` is its own function or a macro calls that,
        // not the library's.
        if library_function_replaced(
            node,
            source,
            "fclose",
            self.project.borrow().as_ref(),
            self.file_path.borrow().as_deref(),
        ) {
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

        let entry_state = solve(
            &cfg,
            |id, state| walker.block(&cfg, id, state, None),
            |_, _, _| {},
        );
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
/// whose merge is union, so a file closed on any path into a block may be
/// closed there. `transfer` applies a block to a state and `on_edge` what
/// taking one edge out of it adds. A block is walked again only when its entry
/// state gains a file or an earlier close of one, and both only move one way,
/// so this ends.
fn solve<V: Clone + Ord>(
    cfg: &FunctionCfg,
    transfer: impl Fn(BlockId, &mut BTreeMap<String, V>),
    on_edge: impl Fn(BlockId, &CfgEdge, &mut BTreeMap<String, V>),
) -> BTreeMap<BlockId, BTreeMap<String, V>> {
    let mut entry: BTreeMap<BlockId, BTreeMap<String, V>> = BTreeMap::new();
    entry.insert(cfg.entry, BTreeMap::new());
    let mut work = VecDeque::from([cfg.entry]);
    while let Some(id) = work.pop_front() {
        let mut state = entry[&id].clone();
        transfer(id, &mut state);
        for (succ, edge) in cfg.successors(id) {
            let mut state = state.clone();
            on_edge(id, edge, &mut state);
            let first_visit = !entry.contains_key(&succ);
            let into = entry.entry(succ).or_default();
            let mut grew = false;
            for (file, closed) in &state {
                match into.get_mut(file) {
                    Some(have) if *have <= *closed => {}
                    // An earlier close reaches the block: the state is the
                    // same files, but its messages name another line.
                    Some(have) => {
                        *have = closed.clone();
                        grew = true;
                    }
                    None => {
                        into.insert(file.clone(), closed.clone());
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

/// A descriptor that may be closed at a program point, with what ends that:
/// the names its spelling reads and the members it goes through.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ClosedFd {
    line: usize,
    byte: usize,
    spelling: String,
    /// The identifiers the spelling reads: `fd`; `ctx` in `ctx->fd`; `fds` and
    /// `i` in `fds[i]`. Assigning one means the spelling names another object.
    names: BTreeSet<String>,
    /// The members the spelling goes through: `fd` in `ctx->fd`.
    members: BTreeSet<String>,
    /// Whether code the function cannot see can write it: a member, an
    /// element, a file-scope or `static` object. A local no `&` reaches and a
    /// parameter cannot be written that way.
    shared: bool,
}

type ClosedFds = BTreeMap<String, ClosedFd>;

/// What a file's calls to a function resolve to.
struct CallNames {
    /// `#define CLOSE close`, every arm: a build in which it is `close` is
    /// enough (ADR-0010). A name the file `#undef`s is not one: its definitions
    /// hold in turn, not in alternative builds.
    aliases: HashMap<String, Vec<String>>,
    /// Library names the file gives its own definitions.
    redefined: HashSet<String>,
}

impl CallNames {
    /// Whether a call spelled `name` reaches `target`.
    fn reaches(&self, name: &str, target: &str) -> bool {
        resolve_macro_alias_where(&self.aliases, name, |n| n == target).is_some()
    }

    /// Whether a call spelled `name` is to the C or POSIX library, which does
    /// not write what it is not given.
    fn is_library(&self, name: &str) -> bool {
        resolve_macro_alias_where(&self.aliases, name, |n| {
            is_iso_c_or_posix_function(n) && !self.redefined.contains(n)
        })
        .is_some()
    }
}

impl Fio46C {
    fn scan_descriptors(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut aliases = collect_macro_alias_alternatives(node, source);
        for undef in undefined_names(node, source) {
            aliases.remove(&undef);
        }
        let names = CallNames {
            aliases,
            redefined: library_names_redefined_among(node, source, is_iso_c_or_posix_function),
        };
        let functions: Vec<_> = query::find_descendants_of_kind(*node, "function_definition")
            .into_iter()
            .filter(|func| closes_a_descriptor(func, source, &names))
            .collect();
        // A file whose `close` is its own function or a macro calls that, not
        // the library's.
        if functions.is_empty()
            || library_function_replaced(
                node,
                source,
                "close",
                self.project.borrow().as_ref(),
                self.file_path.borrow().as_deref(),
            )
        {
            return;
        }
        let settings = Arc::clone(&self.settings.borrow());
        let noreturn = noreturn_names_for_file(
            self.noreturn_functions.borrow().get(&settings),
            node,
            source,
            &settings,
        );
        let arms = PreprocArms::collect(node);
        for func in functions {
            self.analyze_descriptors(&func, source, &noreturn, &names, &arms, violations);
        }
    }

    fn analyze_descriptors(
        &self,
        func: &Node,
        source: &str,
        noreturn: &HashSet<String>,
        names: &CallNames,
        arms: &PreprocArms,
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
        let walker = FdWalker {
            func: *func,
            source,
            names,
            addressed: addressed_names(func, source),
        };
        let entry_state = solve(
            &cfg,
            |id, state| walker.block(&cfg, id, state, None),
            |id, edge, state| walker.edge(&cfg, id, edge, state),
        );
        let mut seen = HashSet::new();
        for block in &cfg.blocks {
            let Some(state) = entry_state.get(&block.id) else {
                continue;
            };
            let mut state = state.clone();
            let mut findings = Vec::new();
            walker.block(&cfg, block.id, &mut state, Some(&mut findings));
            for (call, spelling, closed_line, closed_byte) in findings {
                // Two arms of one `#if` chain are never compiled together.
                if arms.exclusive(closed_byte, call.start_byte()) || !seen.insert(call.start_byte())
                {
                    continue;
                }
                let earlier = if closed_byte == call.start_byte() {
                    "this close() on an earlier pass through the loop".to_string()
                } else {
                    format!("close() at line {closed_line}")
                };
                let position = call.start_position();
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    line: position.row + 1,
                    column: position.column + 1,
                    file_path: String::new(),
                    message: format!(
                        "Descriptor '{spelling}' may already be closed by {earlier}. A second close() fails with EBADF, or closes another file if an open has since returned that number."
                    ),
                    suggestion: Some(
                        "Close each descriptor once, or assign it again (-1, or a new open) after the first close()."
                            .to_string(),
                    ),
                    requires_manual_review: None,
                });
            }
        }
    }
}

/// The names some `#undef` in the file ends.
fn undefined_names(root: &Node, source: &str) -> Vec<String> {
    query::find_descendants_of_kind(*root, "preproc_call")
        .iter()
        .filter(|call| {
            call.child_by_field_name("directive")
                .is_some_and(|d| get_node_text(&d, source) == "#undef")
        })
        .filter_map(|call| call.child_by_field_name("argument"))
        .map(|arg| get_node_text(&arg, source).trim().to_string())
        .collect()
}

/// Whether `declarator`, in `decl`, is a `const` object whose value is fixed
/// where it is declared: `const int fd = 3`, a constant by another spelling.
/// One initialized by a call, or a `const` parameter, holds whatever it is given.
fn is_const_constant(decl: &Node, declarator: &Node, source: &str) -> bool {
    let mut cursor = decl.walk();
    let is_const = decl
        .children(&mut cursor)
        .any(|c| c.kind() == "type_qualifier" && get_node_text(&c, source).trim() == "const");
    let value = declarator
        .parent()
        .filter(|parent| parent.kind() == "init_declarator")
        .and_then(|init| init.child_by_field_name("value"));
    is_const
        && value.is_some_and(|value| {
            value.kind() != "call_expression"
                && query::find_descendants_of_kind(value, "call_expression").is_empty()
        })
}

/// The argument of `call` when it calls `close` with one argument.
fn close_argument<'a>(call: &Node<'a>, source: &str, names: &CallNames) -> Option<Node<'a>> {
    let name = called_function_name(call, source)?;
    if !names.reaches(&name, "close") {
        return None;
    }
    let args = call.child_by_field_name("arguments")?;
    (args.named_child_count() == 1)
        .then(|| args.named_child(0))
        .flatten()
}

/// Whether `func` spells a call to `close`: the cheap test before a CFG.
fn closes_a_descriptor(func: &Node, source: &str, names: &CallNames) -> bool {
    query::find_descendants_of_kind(*func, "call_expression")
        .iter()
        .any(|call| {
            callee_spelling(call, source).is_some_and(|callee| names.reaches(callee, "close"))
                && close_argument(call, source, names).is_some()
        })
}

/// The identifiers in `node`, itself included.
fn identifiers_in(node: &Node, source: &str) -> BTreeSet<String> {
    let mut found: BTreeSet<String> = query::find_descendants_of_kind(*node, "identifier")
        .iter()
        .map(|ident| get_node_text(ident, source).to_string())
        .collect();
    if node.kind() == "identifier" {
        found.insert(get_node_text(node, source).to_string());
    }
    found
}

/// The names under some `&` in `func`: what is written through that pointer
/// is out of sight, so a descriptor read through one of them is never tracked.
fn addressed_names(func: &Node, source: &str) -> BTreeSet<String> {
    query::find_descendants_of_kind(*func, "pointer_expression")
        .iter()
        .filter(|expr| {
            expr.child_by_field_name("operator")
                .is_some_and(|op| get_node_text(&op, source) == "&")
        })
        .filter_map(|expr| expr.child_by_field_name("argument"))
        .flat_map(|operand| identifiers_in(&operand, source))
        .collect()
}

fn strip_parens<'a>(node: &Node<'a>) -> Node<'a> {
    let mut expr = *node;
    while expr.kind() == "parenthesized_expression" {
        match expr.named_child(0) {
            Some(inner) => expr = inner,
            None => break,
        }
    }
    expr
}

/// Whether nothing reads the result of `call`: it is a statement, through
/// parentheses, a cast or a comma.
fn result_discarded(call: &Node) -> bool {
    let mut node = *call;
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "expression_statement" => return true,
            "parenthesized_expression" | "cast_expression" | "comma_expression" => node = parent,
            _ => return false,
        }
    }
    false
}

/// Which way a branch on `close`'s result goes when the close succeeded: the
/// `close` call, and whether success takes the true edge. `None` for any
/// other condition, which leaves neither edge known to be past a close.
fn close_test<'a>(cond: &Node<'a>, source: &str) -> Option<(Node<'a>, bool)> {
    let cond = strip_parens(cond);
    match cond.kind() {
        "call_expression" => Some((cond, false)),
        "unary_expression"
            if cond
                .child_by_field_name("operator")
                .is_some_and(|op| get_node_text(&op, source) == "!") =>
        {
            let (call, on_true) = close_test(&cond.child_by_field_name("argument")?, source)?;
            Some((call, !on_true))
        }
        "binary_expression" => {
            let left = strip_parens(&cond.child_by_field_name("left")?);
            let right = strip_parens(&cond.child_by_field_name("right")?);
            let op = get_node_text(&cond.child_by_field_name("operator")?, source);
            let (call, value, op) = if left.kind() == "call_expression" {
                (left, right, op)
            } else if right.kind() == "call_expression" {
                let flipped = match op {
                    "<" => ">",
                    ">" => "<",
                    "<=" => ">=",
                    ">=" => "<=",
                    same => same,
                };
                (right, left, flipped)
            } else {
                return None;
            };
            // POSIX: 0 on success, -1 otherwise.
            let on_true = match (op, get_node_text(&value, source).replace(' ', "").as_str()) {
                ("==", "0") | ("!=", "-1") | (">=", "0") | (">", "-1") => true,
                ("!=", "0") | ("==", "-1") | ("<", "0") | ("<=", "-1") => false,
                _ => return None,
            };
            Some((call, on_true))
        }
        _ => None,
    }
}

/// Walks statements in evaluation order, updating the closed descriptors and,
/// when asked, recording each `close` of one that may already be closed: the
/// call, the spelling, and the line and byte of the earlier close.
struct FdWalker<'s, 't> {
    func: Node<'t>,
    source: &'s str,
    names: &'s CallNames,
    addressed: BTreeSet<String>,
}

type FdFindings<'t> = Vec<(Node<'t>, String, usize, usize)>;

impl<'t> FdWalker<'_, 't> {
    fn block(
        &self,
        cfg: &FunctionCfg,
        id: BlockId,
        state: &mut ClosedFds,
        mut findings: Option<&mut FdFindings<'t>>,
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

    /// The edge of a branch on `close`'s result that means it succeeded is
    /// past the close. The other is its failure path, where POSIX leaves the
    /// descriptor open or unspecified, so a retry there is not reported.
    fn edge(&self, cfg: &FunctionCfg, id: BlockId, edge: &CfgEdge, state: &mut ClosedFds) {
        let took_true = match edge {
            CfgEdge::TrueBranch => true,
            CfgEdge::FalseBranch => false,
            _ => return,
        };
        let Some((start, end)) = cfg.get_block(id).and_then(|b| b.condition_range) else {
            return;
        };
        let Some(cond) = find_node_at_range(&self.func, start, end) else {
            return;
        };
        let Some((call, on_true)) = close_test(&cond, self.source) else {
            return;
        };
        if on_true == took_true {
            if let Some(arg) = close_argument(&call, self.source, self.names) {
                self.mark_closed(&call, &arg, state);
            }
        }
    }

    /// The key and state of the descriptor `arg` names, when it is an object
    /// the function can follow. Not a constant, or a name no declaration in
    /// reach gives (`STDIN_FILENO`, a macro), or anything computed.
    fn descriptor(&self, call: &Node, arg: &Node) -> Option<(String, ClosedFd)> {
        let expr = strip_parens(arg);
        let shared = match expr.kind() {
            "identifier" => {
                let text = get_node_text(&expr, self.source);
                let (decl, declarator) = resolve_identifier_declarator(&expr, text, self.source)?;
                if declarator.kind() != "identifier"
                    || is_const_constant(&decl, &declarator, self.source)
                {
                    return None;
                }
                let inside = decl.start_byte() >= self.func.start_byte()
                    && decl.end_byte() <= self.func.end_byte();
                let mut cursor = decl.walk();
                let is_static = decl.children(&mut cursor).any(|c| {
                    c.kind() == "storage_class_specifier"
                        && get_node_text(&c, self.source).trim() == "static"
                });
                !inside || is_static
            }
            "field_expression" | "subscript_expression" => {
                if query::find_descendants_of_kinds(
                    expr,
                    &[
                        "call_expression",
                        "update_expression",
                        "assignment_expression",
                    ],
                )
                .into_iter()
                .next()
                .is_some()
                {
                    return None;
                }
                true
            }
            _ => return None,
        };
        let names = identifiers_in(&expr, self.source);
        if !names.is_disjoint(&self.addressed) {
            return None;
        }
        let members = query::find_descendants_of_kind(expr, "field_identifier")
            .iter()
            .map(|field| get_node_text(field, self.source).to_string())
            .collect();
        Some((
            stream_key(&expr, self.source),
            ClosedFd {
                line: call.start_position().row + 1,
                byte: call.start_byte(),
                spelling: get_node_text(&expr, self.source).to_string(),
                names,
                members,
                shared,
            },
        ))
    }

    fn mark_closed(&self, call: &Node, arg: &Node, state: &mut ClosedFds) {
        if let Some((key, closed)) = self.descriptor(call, arg) {
            state.entry(key).or_insert(closed);
        }
    }

    fn expr(
        &self,
        node: &Node<'t>,
        state: &mut ClosedFds,
        findings: &mut Option<&mut FdFindings<'t>>,
    ) {
        match node.kind() {
            "sizeof_expression" | "alignof_expression" | "offsetof_expression" => {}
            "function_definition" | "compound_statement" => {}
            "call_expression" => self.call(node, state, findings),
            "assignment_expression" => {
                if let Some(right) = node.child_by_field_name("right") {
                    self.expr(&right, state, findings);
                }
                if let Some(left) = node.child_by_field_name("left") {
                    self.expr(&left, state, findings);
                    self.written(&left, state);
                }
            }
            "update_expression" => {
                if let Some(argument) = node.child_by_field_name("argument") {
                    self.written(&argument, state);
                }
            }
            "init_declarator" => {
                if let Some(value) = node.child_by_field_name("value") {
                    self.expr(&value, state, findings);
                }
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    forget_names(&identifiers_in(&declarator, self.source), state);
                }
            }
            "declaration" => {
                let mut cursor = node.walk();
                for declarator in node.children_by_field_name("declarator", &mut cursor) {
                    if declarator.kind() == "init_declarator" {
                        self.expr(&declarator, state, findings);
                    } else {
                        forget_names(&identifiers_in(&declarator, self.source), state);
                    }
                }
            }
            _ => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    self.expr(&child, state, findings);
                }
            }
        }
    }

    /// `target` is assigned. A name assigned means every spelling that reads
    /// it names something else now. A member assigned ends the spellings
    /// through that member, by whatever pointer. Anything else, as `*p` and
    /// `a[i]`, may be any shared object.
    fn written(&self, target: &Node, state: &mut ClosedFds) {
        let target = strip_parens(target);
        match target.kind() {
            "identifier" => forget_names(&identifiers_in(&target, self.source), state),
            "field_expression" => {
                if let Some(field) = target.child_by_field_name("field") {
                    let member = get_node_text(&field, self.source);
                    state.retain(|_, closed| !closed.members.contains(member));
                }
            }
            _ => state.retain(|_, closed| !closed.shared),
        }
    }

    fn call(
        &self,
        call: &Node<'t>,
        state: &mut ClosedFds,
        findings: &mut Option<&mut FdFindings<'t>>,
    ) {
        if let Some(arg) = close_argument(call, self.source, self.names) {
            if let Some((key, _)) = self.descriptor(call, &arg) {
                if let (Some(closed), Some(findings)) = (state.get(&key), findings.as_deref_mut()) {
                    findings.push((*call, closed.spelling.clone(), closed.line, closed.byte));
                }
            }
            // A close whose result something reads is known to have closed
            // only on the edge of a test of that result (`FdWalker::edge`).
            if result_discarded(call) {
                self.mark_closed(call, &arg, state);
            }
            return;
        }
        let name = called_function_name(call, self.source);
        let args: Vec<Node<'t>> = call
            .child_by_field_name("arguments")
            .map(|args| {
                let mut cursor = args.walk();
                args.named_children(&mut cursor).collect()
            })
            .unwrap_or_default();
        for arg in &args {
            self.expr(arg, state, findings);
        }
        if name.as_deref().is_some_and(|n| self.names.is_library(n)) {
            // `dup2(x, fd)` opens `fd` without assigning it.
            if name
                .as_deref()
                .is_some_and(|n| self.names.reaches(n, "dup2"))
            {
                if let Some(target) = args.get(1) {
                    let names = identifiers_in(&strip_parens(target), self.source);
                    forget_names(&names, state);
                }
            }
            // `pipe(fds)` and `memset(ctx, ...)` write what they are given a
            // pointer to; `read(fds[0], ...)` is given the value and does not.
            for arg in &args {
                let text = get_node_text(&strip_parens(arg), self.source).to_string();
                let names = identifiers_in(arg, self.source);
                state.retain(|_, closed| {
                    !closed.shared || closed.spelling == text || closed.names.is_disjoint(&names)
                });
            }
        } else {
            // A function can write a shared object, and what looks like one
            // can be a macro that assigns its argument.
            state.retain(|_, closed| !closed.shared);
            for arg in &args {
                forget_names(&identifiers_in(arg, self.source), state);
            }
        }
    }
}

/// Ends every closed descriptor whose spelling reads one of `names`.
fn forget_names(names: &BTreeSet<String>, state: &mut ClosedFds) {
    state.retain(|_, closed| closed.names.is_disjoint(names));
}
