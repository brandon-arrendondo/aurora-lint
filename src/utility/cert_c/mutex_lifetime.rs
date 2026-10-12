// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! When a mutex is destroyed while something may still use it: the one
//! analysis CON31-C and POS48-C share (the C11/POSIX twins read one hazard,
//! keyed by the API only in which family each reports).
//!
//! Three hazards, each read from the calls' thread-API contracts
//! ([`thread_api::thread_op`]) and with each mutex identified by declaration
//! ([`thread_api::sync_object`], ADR-0006):
//!
//! - **Destroyed while held**: a function destroys a mutex it locked and has
//!   not unlocked on every path to the destroy.
//! - **Used after destroy**: a function locks, unlocks, waits with or
//!   destroys again a mutex it destroyed on every path to that use, with no
//!   initialization in between.
//! - **Destroyed while threads may run**: a destroy while a thread whose
//!   start routine locks the mutex may still be running. Either the destroy
//!   is in a start routine and another thread running a routine that locks
//!   the mutex may run beside it (CERT's own example: the last worker
//!   destroys the lock), or the destroying function created such a thread
//!   into a local handle and has not joined it.
//!
//! The first two are read per function along its statements: a lock counts
//! as held only when it is held on every path to the destroy (a branch that
//! returns drops out; a label, which a `goto` may reach holding anything,
//! forgets everything), and only a lock that waits for the mutex counts (a
//! try or timed lock may fail). A call that hands the mutex to any other
//! function may initialize or unlock it there, so it ends what is known about
//! that mutex.
//!
//! What this file cannot see is not reported: a destroy reached through a
//! call from a start routine, a lock held by a caller, a start routine
//! defined in another file, a thread whose handle another function could
//! join. An unlock with no lock held on some path needs the held-lock regions
//! the analysis layer does not have yet.

use crate::analyze::cfg::get_function_name;
use crate::settings::threads::{Blocking, Role, ThreadOpKind};
use crate::utility::cert_c::ast_utils::{
    declaration_has_storage_class, find_containing_function, get_node_text,
    resolve_identifier_binding, IdentifierBinding,
};
use crate::utility::cert_c::thread_api::{self, ProjectFunctions, SyncObject, ThreadCall};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// What makes one mutex operation unsafe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutexHazard {
    /// A destroy of a mutex this function still holds.
    DestroyedWhileHeld {
        /// The line of the lock.
        lock_line: usize,
    },
    /// A use of a mutex this function destroyed.
    UsedAfterDestroy {
        /// The line of the destroy.
        destroy_line: usize,
    },
    /// A destroy while a thread whose start routine locks the mutex may
    /// still run.
    DestroyedWhileThreadsRun {
        /// The start routine that locks the mutex.
        entry: String,
        /// True when the destroy is itself in a start routine and the
        /// thread runs beside it; false when this function created the
        /// thread and has not joined it.
        sibling: bool,
    },
}

/// One unsafe mutex operation.
pub struct MutexFinding<'a> {
    /// The operation: a destroy, or for a use after destroy, the use.
    pub call: ThreadCall<'a>,
    /// Its call expression.
    pub node: Node<'a>,
    /// The mutex as the call writes it, without `&`.
    pub mutex: String,
    /// What makes it unsafe.
    pub hazard: MutexHazard,
}

/// Every unsafe mutex operation in the file under `root`, in source order.
/// A destroy that is unsafe in more than one way is reported once per way.
pub fn mutex_findings<'a>(
    root: &Node<'a>,
    source: &str,
    project: Option<&ProjectFunctions>,
) -> Vec<MutexFinding<'a>> {
    let threads = Threads::collect(root, source, project);
    let mut findings = Vec::new();
    for func in query::find_descendants_of_kind(*root, "function_definition") {
        let Some(body) = func.child_by_field_name("body") else {
            continue;
        };
        let walk = Walk {
            source,
            project,
            threads: &threads,
            function: func,
            exits: RefCell::new(Vec::new()),
        };
        walk.statement(body, Some(Known::default()), &mut findings);
    }
    findings.sort_by_key(|f| f.node.start_byte());
    findings
}

/// What is known about the mutexes at one point of a function, on every
/// path that reaches it. `None` is a point no path reaches.
type State = Option<Known>;

#[derive(Debug, Clone, Default)]
struct Known {
    /// Mutexes held, with the line that locked each.
    held: HashMap<SyncObject, usize>,
    /// Mutexes destroyed, with the line that destroyed each.
    destroyed: HashMap<SyncObject, usize>,
}

/// What holds on both of two paths that join.
fn meet(a: State, b: State) -> State {
    match (a, b) {
        (None, other) | (other, None) => other,
        (Some(a), Some(b)) => Some(Known {
            held: intersect(a.held, &b.held),
            destroyed: intersect(a.destroyed, &b.destroyed),
        }),
    }
}

fn intersect(
    a: HashMap<SyncObject, usize>,
    b: &HashMap<SyncObject, usize>,
) -> HashMap<SyncObject, usize> {
    a.into_iter()
        .filter_map(|(k, line)| b.get(&k).map(|other| (k, line.min(*other))))
        .collect()
}

/// The thread creations and joins in the file, and which mutexes each start
/// routine this file defines locks.
struct Threads {
    creations: Vec<Creation>,
    /// Each join: its function's start byte, its own start byte, the handle.
    joins: Vec<(usize, usize, SyncObject)>,
    /// Each function this file defines, by name, with the mutexes it locks
    /// (whole arrays: an element locked through another function's index is
    /// the same array).
    locks: HashMap<String, HashSet<SyncObject>>,
    /// Functions defined in this file that join some thread.
    joining: HashSet<String>,
}

struct Creation {
    /// The start byte of the function the creation is in.
    function: usize,
    start: usize,
    entry: Option<String>,
    /// The handle's whole array, when the handle names an object.
    handle: Option<SyncObject>,
    /// The handle's root name, when it is a local of the creating function
    /// that no other function can join.
    local_handle: Option<String>,
    /// Whether the creation is in a loop, starting more than one thread.
    in_loop: bool,
}

impl Threads {
    fn collect(root: &Node, source: &str, project: Option<&ProjectFunctions>) -> Threads {
        let mut threads = Threads {
            creations: Vec::new(),
            joins: Vec::new(),
            locks: HashMap::new(),
            joining: HashSet::new(),
        };
        for func in query::find_descendants_of_kind(*root, "function_definition") {
            if let Some(name) = get_function_name(&func, source) {
                threads.locks.entry(name.to_string()).or_default();
            }
        }
        for node in query::find_descendants_of_kind(*root, "call_expression") {
            let Some(call) = thread_api::thread_op(&node, source, project) else {
                continue;
            };
            let Some(func) = find_containing_function(&node) else {
                continue;
            };
            let func_name = get_function_name(&func, source).map(str::to_string);
            match call.kind() {
                ThreadOpKind::ThreadCreate => {
                    let handle = call.operand(Role::Handle);
                    threads.creations.push(Creation {
                        function: func.start_byte(),
                        start: node.start_byte(),
                        entry: call.entry_function(source),
                        handle: handle
                            .and_then(|h| thread_api::sync_object(&h, source))
                            .map(|h| h.array()),
                        local_handle: handle.and_then(|h| local_root(h, source)),
                        in_loop: in_loop(&node, &func),
                    });
                }
                ThreadOpKind::ThreadJoin => {
                    if let Some(handle) = call
                        .operand(Role::Handle)
                        .and_then(|h| thread_api::sync_object(&h, source))
                    {
                        threads
                            .joins
                            .push((func.start_byte(), node.start_byte(), handle.array()));
                    }
                    if let Some(name) = func_name {
                        threads.joining.insert(name);
                    }
                }
                ThreadOpKind::MutexLock => {
                    if let (Some(name), Some(mutex)) = (
                        func_name,
                        call.operand(Role::Object)
                            .and_then(|m| thread_api::sync_object(&m, source)),
                    ) {
                        threads.locks.entry(name).or_default().insert(mutex.array());
                    }
                }
                _ => {}
            }
        }
        threads
    }

    /// Whether `entry` is a start routine this file defines that locks
    /// `mutex`.
    fn locks(&self, entry: &str, mutex: &SyncObject) -> bool {
        self.locks.get(entry).is_some_and(|m| m.contains(mutex))
    }

    /// Whether the thread `creation` started is joined in its own function
    /// between `from` and `to` (start bytes).
    fn joined_between(&self, creation: &Creation, from: usize, to: usize) -> bool {
        creation.handle.as_ref().is_some_and(|handle| {
            self.joins.iter().any(|(function, at, joined)| {
                *function == creation.function && from < *at && *at < to && joined == handle
            })
        })
    }

    /// The start routine of a thread that may run beside one running
    /// `function` and that locks `mutex`, when `function` is a start routine.
    fn sibling_locker(&self, function: &str, mutex: &SyncObject) -> Option<String> {
        let own: Vec<&Creation> = self
            .creations
            .iter()
            .filter(|c| c.entry.as_deref() == Some(function))
            .collect();
        if own.is_empty() {
            return None;
        }
        self.creations.iter().find_map(|other| {
            let entry = other.entry.as_deref()?;
            if !self.locks(entry, mutex) {
                return None;
            }
            let concurrent = own.iter().any(|mine| {
                if std::ptr::eq(*mine, other) {
                    return other.in_loop;
                }
                if mine.function != other.function {
                    return true;
                }
                // A thread joined before the other is created never runs
                // beside it.
                let (first, second) = if mine.start < other.start {
                    (*mine, other)
                } else {
                    (other, *mine)
                };
                !self.joined_between(first, first.start, second.start)
            });
            concurrent.then(|| entry.to_string())
        })
    }
}

/// One function's walk.
struct Walk<'s, 'a> {
    source: &'s str,
    project: Option<&'s ProjectFunctions>,
    threads: &'s Threads,
    function: Node<'a>,
    /// For each loop and `switch` the walk is inside, innermost last: what
    /// is known where a `break` or `continue` leaves it.
    exits: RefCell<Vec<Exit>>,
}

/// The states that leave one loop or `switch` early.
struct Exit {
    is_loop: bool,
    breaks: State,
    continues: State,
}

impl<'s, 'a> Walk<'s, 'a> {
    /// `state` after `node` runs, recording each finding met on the way.
    fn statement(&self, node: Node<'a>, state: State, out: &mut Vec<MutexFinding<'a>>) -> State {
        match node.kind() {
            "compound_statement" | "else_clause" | "preproc_else" => {
                self.sequence(node, state, out)
            }
            "if_statement" => {
                let state = self.field(node, "condition", state, out);
                let then = node
                    .child_by_field_name("consequence")
                    .map_or(state.clone(), |c| self.statement(c, state.clone(), out));
                let other = match node.child_by_field_name("alternative") {
                    Some(alternative) => self.statement(alternative, state, out),
                    None => state,
                };
                meet(then, other)
            }
            "preproc_if" | "preproc_ifdef" | "preproc_elif" | "preproc_elifdef" => {
                let alternative = node.child_by_field_name("alternative");
                let mut then = state.clone();
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if Some(child) == alternative
                        || Some(child) == node.child_by_field_name("condition")
                        || Some(child) == node.child_by_field_name("name")
                    {
                        continue;
                    }
                    then = self.statement(child, then, out);
                }
                let other = match alternative {
                    Some(alternative) => self.statement(alternative, state, out),
                    None => state,
                };
                meet(then, other)
            }
            "while_statement" | "for_statement" => {
                let mut state = self.field(node, "initializer", state, out);
                state = self.field(node, "condition", state, out);
                let (body, exit) = self.breakable(true, || {
                    node.child_by_field_name("body")
                        .map_or(state.clone(), |b| self.statement(b, state.clone(), out))
                });
                let body = self.field(node, "update", meet(body, exit.continues), out);
                meet(meet(state, body), exit.breaks)
            }
            "do_statement" => {
                let (body, exit) = self.breakable(true, || {
                    node.child_by_field_name("body")
                        .map_or(state.clone(), |b| self.statement(b, state.clone(), out))
                });
                let body = self.field(node, "condition", meet(body, exit.continues), out);
                meet(meet(state, body), exit.breaks)
            }
            "switch_statement" => {
                let entry = self.field(node, "condition", state, out);
                let Some(body) = node.child_by_field_name("body") else {
                    return entry;
                };
                let mut has_default = false;
                let (end, exit) = self.breakable(false, || {
                    let mut current: State = None;
                    let mut cursor = body.walk();
                    for child in body.named_children(&mut cursor) {
                        if child.kind() == "case_statement" {
                            has_default |= child.child_by_field_name("value").is_none();
                            current = meet(current, entry.clone());
                            current = self.sequence_from(child, current, out, true);
                        } else {
                            current = self.statement(child, current, out);
                        }
                    }
                    current
                });
                let end = meet(end, exit.breaks);
                if has_default {
                    end
                } else {
                    meet(end, entry)
                }
            }
            "break_statement" | "continue_statement" => {
                let state = self.calls(node, state, out);
                let mut exits = self.exits.borrow_mut();
                let is_break = node.kind() == "break_statement";
                let target = exits.iter_mut().rev().find(|e| is_break || e.is_loop);
                if let Some(exit) = target {
                    let slot = if is_break {
                        &mut exit.breaks
                    } else {
                        &mut exit.continues
                    };
                    *slot = meet(slot.take(), state);
                }
                None
            }
            "return_statement" | "goto_statement" => {
                self.calls(node, state, out);
                None
            }
            "labeled_statement" => {
                // A `goto` may arrive here from any point.
                let state = Some(Known::default());
                self.sequence_from(node, state, out, true)
            }
            "comment" => state,
            _ => self.calls(node, state, out),
        }
    }

    /// Run `body` as the inside of a loop (`is_loop`) or `switch`, returning
    /// its end state and the states its `break`s and `continue`s leave with.
    fn breakable(&self, is_loop: bool, body: impl FnOnce() -> State) -> (State, Exit) {
        self.exits.borrow_mut().push(Exit {
            is_loop,
            breaks: None,
            continues: None,
        });
        let end = body();
        let exit = self.exits.borrow_mut().pop().expect("pushed above");
        (end, exit)
    }

    /// `state` after each statement child of `node` runs in turn.
    fn sequence(&self, node: Node<'a>, state: State, out: &mut Vec<MutexFinding<'a>>) -> State {
        self.sequence_from(node, state, out, false)
    }

    /// [`Self::sequence`], skipping a case's value or a label's name when
    /// `skip_head` is set.
    fn sequence_from(
        &self,
        node: Node<'a>,
        mut state: State,
        out: &mut Vec<MutexFinding<'a>>,
        skip_head: bool,
    ) -> State {
        let head = [
            node.child_by_field_name("value"),
            node.child_by_field_name("label"),
        ];
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if skip_head && head.contains(&Some(child)) {
                continue;
            }
            state = self.statement(child, state, out);
        }
        state
    }

    /// `state` after the expression in `node`'s `field` runs.
    fn field(
        &self,
        node: Node<'a>,
        field: &str,
        state: State,
        out: &mut Vec<MutexFinding<'a>>,
    ) -> State {
        match node.child_by_field_name(field) {
            Some(child) => self.calls(child, state, out),
            None => state,
        }
    }

    /// `state` after the calls in the expression or simple statement `node`
    /// run, in source order.
    fn calls(&self, node: Node<'a>, state: State, out: &mut Vec<MutexFinding<'a>>) -> State {
        let mut known = state?;
        let mut calls = query::find_descendants_of_kind(node, "call_expression");
        if node.kind() == "call_expression" {
            calls.insert(0, node);
        }
        calls.sort_by_key(|c| c.start_byte());
        calls.dedup_by_key(|c| c.id());
        for call_node in calls {
            match thread_api::thread_op(&call_node, self.source, self.project) {
                Some(call) => self.operation(call, call_node, &mut known, out),
                None => self.hand_off(call_node, &mut known),
            }
        }
        Some(known)
    }

    /// Apply one thread-API call to what is known.
    fn operation(
        &self,
        call: ThreadCall<'a>,
        node: Node<'a>,
        known: &mut Known,
        out: &mut Vec<MutexFinding<'a>>,
    ) {
        let operand = match call.kind() {
            ThreadOpKind::MutexInit
            | ThreadOpKind::MutexLock
            | ThreadOpKind::MutexUnlock
            | ThreadOpKind::MutexDestroy => call.operand(Role::Object),
            ThreadOpKind::CondWait => call.operand(Role::Mutex),
            _ => None,
        };
        let Some(operand) = operand else {
            return;
        };
        let Some(mutex) = thread_api::sync_object(&operand, self.source) else {
            return;
        };
        let line = node.start_position().row + 1;
        let spelling = mutex_spelling(&operand, self.source);
        let kind = call.kind();
        if kind == ThreadOpKind::MutexInit {
            known.destroyed.remove(&mutex);
            known.held.remove(&mutex);
            return;
        }
        if let Some(&destroy_line) = known.destroyed.get(&mutex) {
            out.push(MutexFinding {
                call: call.clone(),
                node,
                mutex: spelling.clone(),
                hazard: MutexHazard::UsedAfterDestroy { destroy_line },
            });
        }
        match kind {
            ThreadOpKind::MutexLock if call.op.blocking == Some(Blocking::Always) => {
                known.held.entry(mutex).or_insert(line);
            }
            ThreadOpKind::MutexUnlock => {
                known.held.remove(&mutex);
            }
            ThreadOpKind::MutexDestroy => {
                if let Some(lock_line) = known.held.remove(&mutex) {
                    out.push(MutexFinding {
                        call: call.clone(),
                        node,
                        mutex: spelling.clone(),
                        hazard: MutexHazard::DestroyedWhileHeld { lock_line },
                    });
                }
                if !known.destroyed.contains_key(&mutex) {
                    for hazard in self.running_threads(node, &mutex) {
                        out.push(MutexFinding {
                            call: call.clone(),
                            node,
                            mutex: spelling.clone(),
                            hazard,
                        });
                    }
                }
                known.destroyed.entry(mutex).or_insert(line);
            }
            _ => {}
        }
    }

    /// A call that is no thread-API operation but is handed a mutex may
    /// initialize, lock or unlock it: forget what is known about it.
    fn hand_off(&self, node: Node<'a>, known: &mut Known) {
        if known.held.is_empty() && known.destroyed.is_empty() {
            return;
        }
        let Some(args) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = args.walk();
        for arg in args.named_children(&mut cursor) {
            if let Some(object) = thread_api::sync_object(&arg, self.source) {
                known.held.retain(|m, _| !same_or_within(m, &object));
                known.destroyed.retain(|m, _| !same_or_within(m, &object));
            }
        }
    }

    /// The threads that may still run, locking `mutex`, when the destroy
    /// `node` runs.
    fn running_threads(&self, node: Node<'a>, mutex: &SyncObject) -> Vec<MutexHazard> {
        let whole = mutex.array();
        let mut hazards = Vec::new();
        let function_name = get_function_name(&self.function, self.source);
        if let Some(entry) = function_name.and_then(|f| self.threads.sibling_locker(f, &whole)) {
            hazards.push(MutexHazard::DestroyedWhileThreadsRun {
                entry,
                sibling: true,
            });
        }
        let at = node.start_byte();
        let here = self.function.start_byte();
        let unjoined = self.threads.creations.iter().find(|c| {
            c.function == here
                && c.start < at
                && c.local_handle.is_some()
                && c.entry
                    .as_deref()
                    .is_some_and(|entry| self.threads.locks(entry, &whole))
                && !self.threads.joined_between(c, c.start, at)
                && !self.handed_off_between(c, at)
        });
        if let Some(creation) = unjoined {
            hazards.push(MutexHazard::DestroyedWhileThreadsRun {
                entry: creation.entry.clone().unwrap_or_default(),
                sibling: false,
            });
        }
        hazards
    }

    /// Whether, between `creation` and `at`, the creating function hands its
    /// handle to another function or calls one of this file's functions that
    /// joins a thread: either may join it.
    fn handed_off_between(&self, creation: &Creation, at: usize) -> bool {
        let Some(handle) = creation.local_handle.as_deref() else {
            return true;
        };
        query::find_descendants_of_kind(self.function, "call_expression")
            .into_iter()
            .filter(|c| creation.start < c.start_byte() && c.start_byte() < at)
            .any(|call| {
                if thread_api::thread_op(&call, self.source, self.project).is_some() {
                    return false;
                }
                let callee = call
                    .child_by_field_name("function")
                    .map(|f| get_node_text(&f, self.source).trim().to_string());
                if callee.is_some_and(|f| self.threads.joining.contains(&f)) {
                    return true;
                }
                call.child_by_field_name("arguments").is_some_and(|args| {
                    query::find_descendants_of_kind(args, "identifier")
                        .iter()
                        .any(|id| get_node_text(id, self.source) == handle)
                })
            })
    }
}

/// Whether `inner` is `outer` or one of its elements or members: handing
/// over a structure hands over the mutex inside it.
fn same_or_within(inner: &SyncObject, outer: &SyncObject) -> bool {
    inner.within(outer)
}

/// The mutex as an operation writes it, without `&` and outer parentheses.
fn mutex_spelling(operand: &Node, source: &str) -> String {
    let text = get_node_text(operand, source).trim();
    let text = text.strip_prefix('&').map_or(text, str::trim_start);
    text.trim_start_matches('(')
        .trim_end_matches(')')
        .trim()
        .to_string()
}

/// Whether `node` sits in a loop of `function`.
fn in_loop(node: &Node, function: &Node) -> bool {
    let mut current = node.parent();
    while let Some(n) = current {
        if n.id() == function.id() {
            return false;
        }
        if matches!(
            n.kind(),
            "for_statement" | "while_statement" | "do_statement"
        ) {
            return true;
        }
        current = n.parent();
    }
    false
}

/// The root name of a handle operand when the object lies in a local of the
/// enclosing function without `static`, reached without a pointer: `&t`,
/// `&t[i]`, `&s.t`. Only that function can then join the thread.
fn local_root(operand: Node, source: &str) -> Option<String> {
    let mut node = operand;
    loop {
        node = match node.kind() {
            "parenthesized_expression" => node.named_child(0)?,
            "cast_expression" => node.child_by_field_name("value")?,
            "pointer_expression" if get_node_text(&node, source).trim_start().starts_with('&') => {
                node.child_by_field_name("argument")?
            }
            "subscript_expression" => node.child_by_field_name("argument")?,
            "field_expression"
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|op| get_node_text(&op, source) == ".") =>
            {
                node.child_by_field_name("argument")?
            }
            "identifier" => break,
            _ => return None,
        };
    }
    let name = get_node_text(&node, source);
    match resolve_identifier_binding(&node, name, source)? {
        IdentifierBinding::Local(decl)
            if !declaration_has_storage_class(&decl, "static", source)
                && !declaration_has_storage_class(&decl, "extern", source) =>
        {
            Some(name.to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hazards(source: &str) -> Vec<(usize, String, MutexHazard)> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        mutex_findings(&tree.root_node(), source, None)
            .into_iter()
            .map(|f| (f.node.start_position().row + 1, f.mutex, f.hazard))
            .collect()
    }

    #[test]
    fn a_destroy_of_a_mutex_held_on_every_path() {
        let got = hazards(
            "#include <pthread.h>\n\
             pthread_mutex_t m;\n\
             void f(int c) {\n\
               pthread_mutex_lock(&m);\n\
               if (c) { pthread_mutex_unlock(&m); return; }\n\
               pthread_mutex_destroy(&m);\n\
             }\n\
             void g(int c) {\n\
               pthread_mutex_lock(&m);\n\
               if (c) pthread_mutex_unlock(&m);\n\
               pthread_mutex_destroy(&m);\n\
             }\n\
             void h(void) {\n\
               if (pthread_mutex_trylock(&m) == 0) {}\n\
               pthread_mutex_destroy(&m);\n\
             }",
        );
        assert_eq!(
            got,
            vec![(
                6,
                "m".into(),
                MutexHazard::DestroyedWhileHeld { lock_line: 4 }
            )]
        );
    }

    #[test]
    fn a_break_or_a_label_ends_what_is_known() {
        let got = hazards(
            "#include <threads.h>\n\
             mtx_t m;\n\
             void f(int c) {\n\
               mtx_lock(&m);\n\
               switch (c) { case 1: mtx_unlock(&m); break; default: mtx_unlock(&m); break; }\n\
               mtx_destroy(&m);\n\
             }\n\
             void g(int c) {\n\
               mtx_lock(&m);\n\
               for (;;) { if (c) { mtx_unlock(&m); break; } }\n\
               mtx_destroy(&m);\n\
             }\n\
             void h(int c) {\n\
               mtx_lock(&m);\n\
               if (c) goto out;\n\
               mtx_unlock(&m);\n\
             out:\n\
               mtx_destroy(&m);\n\
             }",
        );
        assert_eq!(got, vec![]);
    }

    #[test]
    fn a_use_after_destroy_until_the_mutex_is_initialized_again() {
        let got = hazards(
            "#include <pthread.h>\n\
             pthread_mutex_t m[2];\n\
             void reinit(pthread_mutex_t *);\n\
             void f(void) {\n\
               pthread_mutex_destroy(&m[0]);\n\
               pthread_mutex_lock(&m[0]);\n\
               pthread_mutex_lock(&m[1]);\n\
               pthread_mutex_unlock(&m[1]);\n\
               pthread_mutex_init(&m[0], 0);\n\
               pthread_mutex_lock(&m[0]);\n\
               pthread_mutex_unlock(&m[0]);\n\
               pthread_mutex_destroy(&m[0]);\n\
               reinit(&m[0]);\n\
               pthread_mutex_destroy(&m[0]);\n\
             }",
        );
        assert_eq!(
            got,
            vec![(
                6,
                "m[0]".into(),
                MutexHazard::UsedAfterDestroy { destroy_line: 5 }
            )]
        );
    }

    #[test]
    fn a_start_routine_destroys_a_mutex_its_siblings_lock() {
        let got = hazards(
            "#include <threads.h>\n\
             mtx_t lock;\n\
             int work(void *a) {\n\
               if (a) { mtx_lock(&lock); mtx_unlock(&lock); } else { mtx_destroy(&lock); }\n\
               return 0;\n\
             }\n\
             int main(void) {\n\
               thrd_t t[4];\n\
               for (int i = 0; i < 4; i++) thrd_create(&t[i], work, 0);\n\
               for (int i = 0; i < 4; i++) thrd_join(t[i], 0);\n\
               return 0;\n\
             }",
        );
        assert_eq!(
            got,
            vec![(
                4,
                "lock".into(),
                MutexHazard::DestroyedWhileThreadsRun {
                    entry: "work".into(),
                    sibling: true
                }
            )]
        );
    }

    #[test]
    fn a_lone_thread_may_destroy_what_only_it_locks() {
        let got = hazards(
            "#include <threads.h>\n\
             mtx_t lock;\n\
             int work(void *a) { mtx_lock(&lock); mtx_unlock(&lock); mtx_destroy(&lock); return 0; }\n\
             int main(void) { thrd_t t; thrd_create(&t, work, 0); thrd_join(t, 0); return 0; }",
        );
        assert_eq!(got, vec![]);
    }

    #[test]
    fn the_creator_destroys_before_joining() {
        let got = hazards(
            "#include <pthread.h>\n\
             pthread_mutex_t lock;\n\
             void *work(void *a) { pthread_mutex_lock(&lock); pthread_mutex_unlock(&lock); return 0; }\n\
             void wait_all(pthread_t *);\n\
             int early(void) {\n\
               pthread_t t;\n\
               pthread_create(&t, 0, work, 0);\n\
               pthread_mutex_destroy(&lock);\n\
               pthread_join(t, 0);\n\
               return 0;\n\
             }\n\
             int joined(void) {\n\
               pthread_t t;\n\
               pthread_create(&t, 0, work, 0);\n\
               pthread_join(t, 0);\n\
               pthread_mutex_destroy(&lock);\n\
               return 0;\n\
             }\n\
             int handed(void) {\n\
               pthread_t t;\n\
               pthread_create(&t, 0, work, 0);\n\
               wait_all(&t);\n\
               pthread_mutex_destroy(&lock);\n\
               return 0;\n\
             }",
        );
        assert_eq!(
            got,
            vec![(
                8,
                "lock".into(),
                MutexHazard::DestroyedWhileThreadsRun {
                    entry: "work".into(),
                    sibling: false
                }
            )]
        );
    }
}
