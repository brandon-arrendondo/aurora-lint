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
//! try or timed lock may fail). A lock reached only through `&&`, `||` or
//! `?:` is not held on every path. A lock whose result decides an `if` is
//! held only on the branch its success takes (C11 and POSIX locks return
//! zero on success), and on neither when the condition's shape does not
//! say which branch that is; a failure branch that falls through rejoins
//! holding it, as an unchecked lock is presumed taken. A call that hands the mutex to any other
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
use crate::utility::cert_c::thread_api::{self, Family, ProjectFunctions, SyncObject, ThreadCall};
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

/// A mutex held where a call is made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldLock {
    /// The mutex as its lock writes it, without `&`.
    pub mutex: String,
    /// The line of the lock.
    pub line: usize,
    /// The family of the lock call.
    pub family: Family,
}

/// A call made while this function holds at least one mutex on every path
/// to it.
pub struct CallUnderLock<'a> {
    /// The call expression.
    pub node: Node<'a>,
    /// The mutexes held, earliest lock first.
    pub held: Vec<HeldLock>,
}

/// Every unsafe mutex operation in the file under `root`, in source order.
/// A destroy that is unsafe in more than one way is reported once per way.
pub fn mutex_findings<'a>(
    root: &Node<'a>,
    source: &str,
    project: Option<&ProjectFunctions>,
) -> Vec<MutexFinding<'a>> {
    walk_file(root, source, project, false).0
}

/// Every call in the file under `root` made while its function holds a
/// mutex on every path to it, in source order: the same walk as
/// [`mutex_findings`] (only a lock that waits for the mutex counts; a
/// returning branch drops out; a label forgets everything; a call handed the
/// mutex ends what is known about it). Lock, unlock and other thread-API
/// calls are included; a caller filters by what it asks about.
pub fn calls_under_lock<'a>(
    root: &Node<'a>,
    source: &str,
    project: Option<&ProjectFunctions>,
) -> Vec<CallUnderLock<'a>> {
    walk_file(root, source, project, true).1
}

fn walk_file<'a>(
    root: &Node<'a>,
    source: &str,
    project: Option<&ProjectFunctions>,
    record: bool,
) -> (Vec<MutexFinding<'a>>, Vec<CallUnderLock<'a>>) {
    let threads = Threads::collect(root, source, project);
    let mut findings = Vec::new();
    let mut under_lock = Vec::new();
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
            under_lock: record.then(|| RefCell::new(Vec::new())),
            deciding: RefCell::new(Vec::new()),
        };
        walk.statement(body, Some(Known::default()), &mut findings);
        if let Some(calls) = walk.under_lock {
            under_lock.extend(calls.into_inner());
        }
    }
    findings.sort_by_key(|f| f.node.start_byte());
    under_lock.sort_by_key(|c| c.node.start_byte());
    (findings, under_lock)
}

/// What is known about the mutexes at one point of a function, on every
/// path that reaches it. `None` is a point no path reaches.
type State = Option<Known>;

#[derive(Debug, Clone, Default)]
struct Known {
    /// Mutexes held, with the lock that took each.
    held: HashMap<SyncObject, HeldLock>,
    /// Mutexes destroyed, with the line that destroyed each.
    destroyed: HashMap<SyncObject, usize>,
}

/// What holds on both of two paths that join.
fn meet(a: State, b: State) -> State {
    match (a, b) {
        (None, other) | (other, None) => other,
        (Some(a), Some(b)) => Some(Known {
            held: a
                .held
                .into_iter()
                .filter_map(|(k, lock)| {
                    let other = b.held.get(&k)?;
                    Some((
                        k,
                        if other.line < lock.line {
                            other.clone()
                        } else {
                            lock
                        },
                    ))
                })
                .collect(),
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
    /// The calls made under a lock, when the walk records them.
    under_lock: Option<RefCell<Vec<CallUnderLock<'a>>>>,
    /// Locks whose result decides the `if` condition being walked: held
    /// only on one branch, set aside until the branches are walked.
    deciding: RefCell<Vec<Deciding>>,
}

/// A lock whose result decides an `if`.
struct Deciding {
    mutex: SyncObject,
    lock: HeldLock,
    /// Whether its success takes the `then` branch, or the `else`.
    success_is_then: bool,
}

/// Where a lock call sits in the expression its statement evaluates.
enum Guard {
    /// Evaluated on every path through the expression, and its result
    /// decides nothing that the walk branches on.
    Always,
    /// Evaluated only on some paths (`&&`, `||`, `?:`), or its success is
    /// not known on any branch the walk takes.
    Never,
    /// Decides the `if` being walked: held on the `then` branch when true.
    Decides { success_is_then: bool },
}

/// The states that leave one loop or `switch` early.
struct Exit {
    is_loop: bool,
    breaks: State,
    continues: State,
}

/// What the walk does when the statement it is inside finishes: the rest of
/// that statement, waiting for its child's end state. The walk keeps these on
/// a stack of its own instead of recursing, because a function nests as many
/// statements as its author writes (thousands, in generated code) and a
/// frame per level overflows a thread's stack (ADR-0017).
enum Frame<'a> {
    /// Run `children[next..]` in turn.
    Sequence {
        children: Vec<Node<'a>>,
        next: usize,
    },
    /// An `if`'s consequence has run; run its alternative from `entry`.
    IfThen {
        alternative: Option<Node<'a>>,
        deciding: Vec<Deciding>,
        entry: State,
    },
    /// An `if`'s alternative has run; join it with the consequence's end.
    IfElse {
        deciding: Vec<Deciding>,
        then: State,
    },
    /// A preprocessor conditional's own branch has run; run its
    /// alternative from `entry`.
    PreprocThen {
        alternative: Option<Node<'a>>,
        entry: State,
    },
    /// A preprocessor conditional's alternative has run; join the two.
    PreprocElse { then: State },
    /// A loop's body has run (its [`Exit`] is the innermost one).
    Loop {
        node: Node<'a>,
        entry: State,
        is_do: bool,
    },
    /// A `switch` body's `children[..next]` have run (its [`Exit`] is the
    /// innermost one).
    Switch {
        children: Vec<Node<'a>>,
        next: usize,
        entry: State,
        has_default: bool,
    },
}

/// The walk's next move: start a statement, or hand an end state to the
/// statement waiting on it.
enum Step<'a> {
    Run(Node<'a>, State),
    Done(State),
}

impl<'s, 'a> Walk<'s, 'a> {
    /// `state` after `node` runs, recording each finding met on the way.
    fn statement(&self, node: Node<'a>, state: State, out: &mut Vec<MutexFinding<'a>>) -> State {
        let mut frames: Vec<Frame<'a>> = Vec::new();
        let mut step = Step::Run(node, state);
        loop {
            step = match step {
                Step::Run(node, state) => self.start(node, state, &mut frames, out),
                Step::Done(end) => match frames.pop() {
                    None => return end,
                    Some(frame) => self.resume(frame, end, &mut frames, out),
                },
            };
        }
    }

    /// Begin `node` from `state`: finish it at once, or leave on `frames`
    /// what remains of it once the child it starts has run.
    fn start(
        &self,
        node: Node<'a>,
        state: State,
        frames: &mut Vec<Frame<'a>>,
        out: &mut Vec<MutexFinding<'a>>,
    ) -> Step<'a> {
        match node.kind() {
            "compound_statement" | "else_clause" | "preproc_else" => {
                frames.push(Frame::Sequence {
                    children: Self::children(node, false),
                    next: 0,
                });
                Step::Done(state)
            }
            "if_statement" => {
                let outer = self.deciding.take();
                let state = self.field(node, "condition", state, out);
                let deciding = self.deciding.replace(outer);
                let then = Self::branch(&deciding, true, &state);
                frames.push(Frame::IfThen {
                    alternative: node.child_by_field_name("alternative"),
                    deciding,
                    entry: state,
                });
                match node.child_by_field_name("consequence") {
                    Some(consequence) => Step::Run(consequence, then),
                    None => Step::Done(then),
                }
            }
            "preproc_if" | "preproc_ifdef" | "preproc_elif" | "preproc_elifdef" => {
                let alternative = node.child_by_field_name("alternative");
                let head = [
                    alternative,
                    node.child_by_field_name("condition"),
                    node.child_by_field_name("name"),
                ];
                let mut cursor = node.walk();
                let children = node
                    .named_children(&mut cursor)
                    .filter(|c| !head.contains(&Some(*c)))
                    .collect();
                frames.push(Frame::PreprocThen {
                    alternative,
                    entry: state.clone(),
                });
                frames.push(Frame::Sequence { children, next: 0 });
                Step::Done(state)
            }
            "while_statement" | "for_statement" | "do_statement" => {
                let is_do = node.kind() == "do_statement";
                let mut state = state;
                if !is_do {
                    state = self.field(node, "initializer", state, out);
                    state = self.field(node, "condition", state, out);
                }
                self.exits.borrow_mut().push(Exit {
                    is_loop: true,
                    breaks: None,
                    continues: None,
                });
                frames.push(Frame::Loop {
                    node,
                    entry: state.clone(),
                    is_do,
                });
                match node.child_by_field_name("body") {
                    Some(body) => Step::Run(body, state),
                    None => Step::Done(state),
                }
            }
            "switch_statement" => {
                let entry = self.field(node, "condition", state, out);
                let Some(body) = node.child_by_field_name("body") else {
                    return Step::Done(entry);
                };
                self.exits.borrow_mut().push(Exit {
                    is_loop: false,
                    breaks: None,
                    continues: None,
                });
                let mut cursor = body.walk();
                frames.push(Frame::Switch {
                    children: body.named_children(&mut cursor).collect(),
                    next: 0,
                    entry,
                    has_default: false,
                });
                Step::Done(None)
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
                Step::Done(None)
            }
            "return_statement" | "goto_statement" => {
                self.calls(node, state, out);
                Step::Done(None)
            }
            "labeled_statement" => {
                // A `goto` may arrive here from any point.
                frames.push(Frame::Sequence {
                    children: Self::children(node, true),
                    next: 0,
                });
                Step::Done(Some(Known::default()))
            }
            "comment" => Step::Done(state),
            _ => Step::Done(self.calls(node, state, out)),
        }
    }

    /// Carry `frame` on now that the child it waited for ended in `end`.
    fn resume(
        &self,
        frame: Frame<'a>,
        end: State,
        frames: &mut Vec<Frame<'a>>,
        out: &mut Vec<MutexFinding<'a>>,
    ) -> Step<'a> {
        match frame {
            Frame::Sequence { children, next } => match children.get(next).copied() {
                Some(child) => {
                    frames.push(Frame::Sequence {
                        children,
                        next: next + 1,
                    });
                    Step::Run(child, end)
                }
                None => Step::Done(end),
            },
            Frame::IfThen {
                alternative,
                deciding,
                entry,
            } => {
                let other = Self::branch(&deciding, false, &entry);
                frames.push(Frame::IfElse {
                    deciding,
                    then: end,
                });
                match alternative {
                    Some(alternative) => Step::Run(alternative, other),
                    None => Step::Done(other),
                }
            }
            Frame::IfElse { deciding, then } => Step::Done(meet(
                Self::rejoin(&deciding, true, then),
                Self::rejoin(&deciding, false, end),
            )),
            Frame::PreprocThen { alternative, entry } => {
                frames.push(Frame::PreprocElse { then: end });
                match alternative {
                    Some(alternative) => Step::Run(alternative, entry),
                    None => Step::Done(entry),
                }
            }
            Frame::PreprocElse { then } => Step::Done(meet(then, end)),
            Frame::Loop { node, entry, is_do } => {
                let exit = self.exits.borrow_mut().pop().expect("pushed at the loop");
                let field = if is_do { "condition" } else { "update" };
                let body = self.field(node, field, meet(end, exit.continues), out);
                Step::Done(meet(meet(entry, body), exit.breaks))
            }
            Frame::Switch {
                children,
                next,
                entry,
                mut has_default,
            } => {
                let Some(child) = children.get(next).copied() else {
                    let exit = self.exits.borrow_mut().pop().expect("pushed at the switch");
                    let end = meet(end, exit.breaks);
                    return Step::Done(if has_default { end } else { meet(end, entry) });
                };
                let is_case = child.kind() == "case_statement";
                has_default |= is_case && child.child_by_field_name("value").is_none();
                let current = if is_case {
                    meet(end, entry.clone())
                } else {
                    end
                };
                frames.push(Frame::Switch {
                    children,
                    next: next + 1,
                    entry,
                    has_default,
                });
                if is_case {
                    frames.push(Frame::Sequence {
                        children: Self::children(child, true),
                        next: 0,
                    });
                    Step::Done(current)
                } else {
                    Step::Run(child, current)
                }
            }
        }
    }

    /// `node`'s statement children, in order, without a case's value or a
    /// label's name when `skip_head` is set.
    fn children(node: Node<'a>, skip_head: bool) -> Vec<Node<'a>> {
        let head = [
            node.child_by_field_name("value"),
            node.child_by_field_name("label"),
        ];
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .filter(|c| !(skip_head && head.contains(&Some(*c))))
            .collect()
    }

    /// The state an `if` branch starts in: a lock that decides the
    /// condition is held on the branch its success takes.
    fn branch(deciding: &[Deciding], then: bool, state: &State) -> State {
        let mut state = state.clone();
        if let Some(known) = state.as_mut() {
            for d in deciding.iter().filter(|d| d.success_is_then == then) {
                known.held.entry(d.mutex.clone()).or_insert(d.lock.clone());
            }
        }
        state
    }

    /// A failure branch that falls through is read as an unchecked lock is:
    /// presumed taken from there on.
    fn rejoin(deciding: &[Deciding], then: bool, mut state: State) -> State {
        if let Some(known) = state.as_mut() {
            for d in deciding.iter().filter(|d| d.success_is_then != then) {
                known.held.entry(d.mutex.clone()).or_insert(d.lock.clone());
            }
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
            if let Some(record) = &self.under_lock {
                if !known.held.is_empty() {
                    let mut held: Vec<HeldLock> = known.held.values().cloned().collect();
                    held.sort_by(|a, b| (a.line, &a.mutex).cmp(&(b.line, &b.mutex)));
                    record.borrow_mut().push(CallUnderLock {
                        node: call_node,
                        held,
                    });
                }
            }
            match thread_api::thread_op(&call_node, self.source, self.project) {
                Some(call) => self.operation(call, call_node, node, &mut known, out),
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
        root: Node<'a>,
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
                let lock = HeldLock {
                    mutex: spelling.clone(),
                    line,
                    family: call.family,
                };
                match lock_guard(node, root, call.family, self.source) {
                    Guard::Always => {
                        known.held.entry(mutex).or_insert(lock);
                    }
                    Guard::Never => {}
                    Guard::Decides { success_is_then } => {
                        self.deciding.borrow_mut().push(Deciding {
                            mutex,
                            lock,
                            success_is_then,
                        })
                    }
                }
            }
            ThreadOpKind::MutexUnlock => {
                known.held.remove(&mutex);
            }
            ThreadOpKind::MutexDestroy => {
                if let Some(HeldLock {
                    line: lock_line, ..
                }) = known.held.remove(&mutex)
                {
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

/// Where the lock `call` sits in `root`, the expression or statement the
/// walk evaluates: under a short-circuit or conditional operand it is not
/// evaluated on every path; as the condition of an `if`, through
/// parentheses, `!`, a comparison with zero (or `thrd_success`) and an
/// assignment, its success picks a branch, for the families whose locks
/// return zero on success; anywhere else in an `if` condition its success
/// is not known on either branch.
fn lock_guard(call: Node, root: Node, family: Family, source: &str) -> Guard {
    // Whether the value reaching the current node is true on failure.
    let mut true_on_failure = true;
    let mut deciding = matches!(family, Family::C11 | Family::Posix);
    let mut current = call;
    while current.id() != root.id() {
        let Some(parent) = current.parent() else {
            break;
        };
        match parent.kind() {
            "binary_expression" => {
                let operator = parent
                    .child_by_field_name("operator")
                    .map(|o| get_node_text(&o, source));
                let right = parent.child_by_field_name("right");
                let left = parent.child_by_field_name("left");
                match operator {
                    Some("&&" | "||") => {
                        if right.is_some_and(|r| r.id() == current.id()) {
                            return Guard::Never;
                        }
                        deciding = false;
                    }
                    Some(op @ ("==" | "!=")) => {
                        let other = if left.is_some_and(|l| l.id() == current.id()) {
                            right
                        } else {
                            left
                        };
                        let zero = other.is_some_and(|o| {
                            matches!(get_node_text(&o, source), "0" | "thrd_success")
                        });
                        if zero && op == "==" {
                            true_on_failure = !true_on_failure;
                        } else if !zero {
                            deciding = false;
                        }
                    }
                    _ => deciding = false,
                }
            }
            "conditional_expression" => {
                if parent
                    .child_by_field_name("condition")
                    .is_none_or(|c| c.id() != current.id())
                {
                    return Guard::Never;
                }
                deciding = false;
            }
            "unary_expression" => {
                let operator = parent
                    .child_by_field_name("operator")
                    .map(|o| get_node_text(&o, source));
                if operator == Some("!") {
                    true_on_failure = !true_on_failure;
                } else {
                    deciding = false;
                }
            }
            "assignment_expression" => {
                if parent
                    .child_by_field_name("right")
                    .is_none_or(|r| r.id() != current.id())
                {
                    deciding = false;
                }
            }
            "parenthesized_expression" => {}
            _ => deciding = false,
        }
        current = parent;
    }
    let in_if_condition = root.parent().is_some_and(|p| {
        p.kind() == "if_statement"
            && p.child_by_field_name("condition")
                .is_some_and(|c| c.id() == root.id())
    });
    if !in_if_condition {
        Guard::Always
    } else if deciding {
        Guard::Decides {
            success_is_then: !true_on_failure,
        }
    } else {
        Guard::Never
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
