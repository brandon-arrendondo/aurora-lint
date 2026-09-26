// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! MEM06-C: Ensure that sensitive data is not written out to disk
//!
//! A buffer is sensitive when it reaches a declared credential sink
//! (`credential_sinks::CREDENTIAL_SINKS`: `LogonUser`'s password, `crypt`'s
//! key, a `PAM_AUTHTOK` item), directly or through a function whose summary
//! says it forwards that parameter to one. That is the rule's checkable form
//! and the Juliet CWE-591 definition; a name like `secret` proves nothing.
//!
//! The rule traces each sensitive buffer back to the object that holds it
//! in this function, through plain copies (`q = p`, `char *q = p`), and
//! reports when that object is a heap allocation or a local array whose
//! pages are never locked. Protection is either
//! - an `mlock`/`VirtualLock` of the buffer (or a call to a function that
//!   locks it) on the path from its allocation to the sink, or a source
//!   function that returns the buffer already locked; or
//! - process-wide protection on the startup path: `main`, or a function
//!   reachable from it, disables core dumps with a zero `RLIMIT_CORE` or
//!   calls `mlockall`.
//!
//! The finding is reported where the unprotected secret is released (its
//! `free`), or at the sink when this function does not release it; the
//! allocation is named in the message (ADR-0012). A buffer that arrives as a
//! parameter is its caller's to protect, so it is judged where it was
//! allocated, not where it is used.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval::resolve_macro_alias;
use crate::analyze::context::{ProjectContext, ScopedTable};
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::init_state::strip_arg_casts;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{get_node_text, resolve_identifier_declarator};
use crate::utility::cert_c::{call_roles, credential_sinks};
use lang_parsing_substrate::query;

/// MEM06-C: Ensure that sensitive data is not written out to disk
#[derive(Default)]
pub struct Mem06C {
    function_summaries: RefCell<ScopedTable<FunctionSummary>>,
    call_graph: RefCell<Arc<HashMap<String, HashSet<String>>>>,
    macro_aliases: RefCell<Arc<HashMap<String, String>>>,
}

impl CertRule for Mem06C {
    fn rule_id(&self) -> &'static str {
        "MEM06-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that sensitive data is not written out to disk"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "MEM06-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.call_graph.borrow_mut() = context.call_graph.clone();
        *self.macro_aliases.borrow_mut() = context.macro_aliases.clone();
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut process_protected: Option<bool> = None;
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function(&func, source, &mut process_protected, violations);
        }
    }
}

/// Where the object holding a sensitive buffer came from.
struct Origin<'a> {
    /// The allocating call, or the array's declaration.
    node: Node<'a>,
    /// How to name it in the message.
    what: String,
    /// A source function that hands the buffer back already locked.
    returned_locked: bool,
}

/// One argument position at which a buffer reaches a credential sink.
struct SinkUse<'a> {
    call: Node<'a>,
    callee: String,
    object: usize,
}

impl Mem06C {
    fn check_function(
        &self,
        func: &Node,
        source: &str,
        process_protected: &mut Option<bool>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(body) = func.child_by_field_name("body") else {
            return;
        };
        let calls: Vec<Node> = query::find_descendants_of_kind(body, "call_expression")
            .into_iter()
            .filter(|c| innermost_function(c).is_some_and(|f| f.id() == func.id()))
            .collect();

        let mut objects = Objects::default();
        let mut sink_uses: Vec<SinkUse> = Vec::new();
        for call in &calls {
            let Some(callee) = self.callee_name(call, source) else {
                continue;
            };
            let args = call_args(call);
            for idx in self.sink_arg_indices(&callee, &args, source) {
                if let Some(object) = args.get(idx).and_then(|a| objects.of(a, source)) {
                    sink_uses.push(SinkUse {
                        call: *call,
                        callee: callee.clone(),
                        object,
                    });
                }
            }
        }
        if sink_uses.is_empty() {
            return;
        }
        objects.union_copies(&body, source);

        let mut reported: HashSet<usize> = HashSet::new();
        for sink in &sink_uses {
            let class = objects.find(sink.object);
            if !reported.insert(class) {
                continue;
            }
            let members = objects.members(class);
            // A parameter is the caller's buffer, and a global's lifetime
            // is not this function's: neither is judged here.
            if members
                .iter()
                .any(|m| objects.info[m].is_param || objects.info[m].is_global)
            {
                continue;
            }
            let first_sink = sink_uses
                .iter()
                .filter(|s| objects.find(s.object) == class)
                .min_by_key(|s| s.call.start_byte())
                .expect("the current sink is in its own class");
            let unprotected = self
                .origins(&body, &members, &objects, source)
                .into_iter()
                .filter(|o| o.node.start_byte() < first_sink.call.start_byte())
                .find(|o| {
                    !o.returned_locked
                        && !self.locked_between(
                            &calls,
                            &body,
                            &o.node,
                            &first_sink.call,
                            &members,
                            &objects,
                            source,
                        )
                });
            let Some(origin) = unprotected else {
                continue;
            };
            if self.process_protected(process_protected) {
                continue;
            }
            let release = calls
                .iter()
                .filter(|c| c.start_byte() > first_sink.call.start_byte())
                .filter(|c| self.callee_name(c, source).as_deref() == Some("free"))
                .filter(|c| {
                    call_args(c)
                        .first()
                        .and_then(|a| objects.lookup(a, source))
                        .is_some_and(|o| objects.find(o) == class)
                })
                .max_by_key(|c| c.start_byte());
            let site = release.unwrap_or(&first_sink.call);
            let var = &objects.info[&first_sink.object].name;
            let origin_line = origin.node.start_position().row + 1;
            let sink_line = first_sink.call.start_position().row + 1;
            let message = if release.is_some() {
                format!(
                    "'{var}' holds a credential (passed to {} at line {sink_line}) and is freed \
                     here without its pages ever being locked: {} at line {origin_line} may \
                     have been written to swap or a core dump.",
                    first_sink.callee, origin.what
                )
            } else {
                format!(
                    "'{var}' reaches a credential sink ({}) in memory whose pages are never \
                     locked: {} at line {origin_line} may be written to swap or a core dump.",
                    first_sink.callee, origin.what
                )
            };
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                line: site.start_position().row + 1,
                column: site.start_position().column + 1,
                file_path: String::new(),
                message,
                suggestion: Some(
                    "Lock the buffer with mlock() (POSIX) or VirtualLock() (Windows) before \
                     the secret is stored in it, or disable core dumps with \
                     setrlimit(RLIMIT_CORE) set to zero at startup."
                        .to_string(),
                ),
                requires_manual_review: None,
            });
        }
    }

    /// The callee of a direct call, through the project's `#define` aliases.
    fn callee_name(&self, call: &Node, source: &str) -> Option<String> {
        let function = call.child_by_field_name("function")?;
        if function.kind() != "identifier" {
            return None;
        }
        let name = get_node_text(&function, source);
        let aliases = self.macro_aliases.borrow();
        let resolved = resolve_macro_alias(&aliases, &name);
        if resolved != name && !self.function_summaries.borrow().contains_key(&name) {
            Some(resolved.to_string())
        } else {
            Some(name.to_string())
        }
    }

    /// The argument indices of one call that receive a secret. A callee the
    /// project defines answers from its summary, since the project's own
    /// `crypt` is not libc's; anything else from the declared table.
    fn sink_arg_indices(&self, callee: &str, args: &[Node], source: &str) -> Vec<usize> {
        if let Some(summary) = self.function_summaries.borrow().get(callee) {
            let mut idx: Vec<usize> = summary.credential_sink_params.iter().copied().collect();
            idx.sort_unstable();
            return idx;
        }
        let texts: Vec<String> = args
            .iter()
            .map(|a| get_node_text(a, source).trim().to_string())
            .collect();
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        credential_sinks::sink_args_of_call(callee, &refs)
    }

    /// Every allocation, or the local array, that can hold one class of
    /// copies. Each is judged on its own: a branch that allocates without
    /// locking is a violation even when another branch locks.
    fn origins<'a>(
        &self,
        body: &Node<'a>,
        members: &[usize],
        objects: &Objects<'a>,
        source: &str,
    ) -> Vec<Origin<'a>> {
        for m in members {
            let info = &objects.info[m];
            if info.is_array {
                return vec![Origin {
                    node: info.declarator,
                    what: format!("the array '{}'", info.name),
                    returned_locked: false,
                }];
            }
        }
        let summaries = self.function_summaries.borrow();
        let mut found: Vec<Origin<'a>> = Vec::new();
        for (target, value) in assignments(body, source) {
            let Some(object) = objects.lookup(&target, source) else {
                continue;
            };
            if !members.contains(&object) {
                continue;
            }
            let value = strip_arg_casts(&value);
            if value.kind() != "call_expression" {
                continue;
            }
            let Some(callee) = self.callee_name(&value, source) else {
                continue;
            };
            let summary = summaries.get(&callee);
            let allocates = match summary {
                Some(s) => s.returns_allocation,
                None => call_roles::is_allocator_call(&callee),
            };
            if allocates {
                found.push(Origin {
                    node: value,
                    what: format!("the block from {callee}()"),
                    returned_locked: summary.is_some_and(|s| s.returns_locked),
                });
            }
        }
        found
    }

    /// Whether a page lock of the buffer runs on the way from `origin` to
    /// the first store into it (or to `sink`, whichever comes first): after
    /// the allocation, and not inside a block or branch the allocation is
    /// not also inside, so every path from the allocation passes it. Locking
    /// after the secret is written leaves the pages it sat in unprotected.
    /// A call to a project function whose summary locks that argument counts
    /// like `VirtualLock` itself.
    fn locked_between(
        &self,
        calls: &[Node],
        body: &Node,
        origin: &Node,
        sink: &Node,
        members: &[usize],
        objects: &Objects,
        source: &str,
    ) -> bool {
        let summaries = self.function_summaries.borrow();
        let names_member = |a: &Node| {
            objects
                .lookup(a, source)
                .is_some_and(|o| members.contains(&o))
        };
        let locked_args = |call: &Node| -> Vec<usize> {
            match self.callee_name(call, source) {
                Some(callee) => match summaries.get(&callee) {
                    Some(s) => s.locks_params.iter().copied().collect(),
                    None if credential_sinks::is_page_lock_call(&callee) => vec![0],
                    None => Vec::new(),
                },
                None => Vec::new(),
            }
        };
        let is_lock_of_member = |call: &Node| {
            let args = call_args(call);
            locked_args(call)
                .iter()
                .any(|&i| args.get(i).is_some_and(&names_member))
        };

        // The first store into the buffer after the allocation: a call that
        // is handed the buffer (not a lock, a clear or the free), or a write
        // through it (`p[i] = c`, `*p = c`).
        let call_stores = calls.iter().filter(|c| {
            c.start_byte() > origin.end_byte()
                && !is_lock_of_member(c)
                && self
                    .callee_name(c, source)
                    .is_none_or(|n| n != "free" && !call_roles::is_memory_clearing_call(&n))
                && call_args(c).iter().any(&names_member)
        });
        let write_stores = assignments(body, source)
            .into_iter()
            .filter_map(|(target, _)| {
                let base = match target.kind() {
                    "subscript_expression" => target.child_by_field_name("argument"),
                    "pointer_expression" => target.child_by_field_name("argument"),
                    _ => None,
                }?;
                (target.start_byte() > origin.end_byte() && names_member(&base)).then_some(target)
            });
        let bound = call_stores
            .map(|c| c.start_byte())
            .chain(write_stores.map(|t| t.start_byte()))
            .chain(std::iter::once(sink.start_byte()))
            .min()
            .unwrap_or(sink.start_byte());

        calls.iter().any(|call| {
            call.start_byte() > origin.start_byte()
                && call.start_byte() < bound
                && is_lock_of_member(call)
                && on_every_path_from(call, origin)
        })
    }

    /// Whether `main`, or a function reachable from it, protects the whole
    /// process. Computed once per file.
    fn process_protected(&self, cached: &mut Option<bool>) -> bool {
        if let Some(v) = *cached {
            return v;
        }
        let summaries = self.function_summaries.borrow();
        let protectors: HashSet<&str> = summaries
            .iter()
            .filter(|(_, s)| s.protects_process_memory)
            .map(|(n, _)| n.as_str())
            .collect();
        let mut result = false;
        if !protectors.is_empty() {
            let graph = self.call_graph.borrow();
            let mut seen: HashSet<&str> = HashSet::new();
            let mut queue: VecDeque<&str> = VecDeque::from(["main"]);
            while let Some(f) = queue.pop_front() {
                if !seen.insert(f) {
                    continue;
                }
                if protectors.contains(f) {
                    result = true;
                    break;
                }
                if let Some(callees) = graph.get(f) {
                    queue.extend(callees.iter().map(String::as_str));
                }
            }
        }
        *cached = Some(result);
        result
    }
}

/// What the rule knows about one declared object.
struct ObjectInfo<'a> {
    name: String,
    declarator: Node<'a>,
    is_param: bool,
    is_global: bool,
    is_array: bool,
}

/// The objects a function's sink arguments and copies name, keyed by their
/// declarator, with copies unioned into classes.
#[derive(Default)]
struct Objects<'a> {
    info: HashMap<usize, ObjectInfo<'a>>,
    parent: HashMap<usize, usize>,
}

impl<'a> Objects<'a> {
    /// The object an expression names, casts and parentheses peeled, by
    /// resolving the identifier to its declaration (ADR-0006).
    fn of(&mut self, expr: &Node<'a>, source: &str) -> Option<usize> {
        let ident = strip_arg_casts(expr);
        if ident.kind() != "identifier" {
            return None;
        }
        let name = get_node_text(&ident, source);
        let (decl, declarator) = resolve_identifier_declarator(&ident, &name, source)?;
        let key = declarator.start_byte();
        if self.info.contains_key(&key) {
            return Some(key);
        }
        self.info.entry(key).or_insert_with(|| ObjectInfo {
            is_param: decl.kind() == "parameter_declaration",
            is_global: innermost_function(&decl).is_none(),
            is_array: declarator.kind() == "array_declarator",
            name: name.to_string(),
            declarator,
        });
        self.parent.entry(key).or_insert(key);
        Some(key)
    }

    /// [`Objects::of`] without recording a new object: an expression naming
    /// nothing the sink analysis saw belongs to no class.
    fn lookup(&self, expr: &Node<'a>, source: &str) -> Option<usize> {
        let ident = strip_arg_casts(expr);
        if ident.kind() != "identifier" {
            return None;
        }
        let name = get_node_text(&ident, source);
        let (_, declarator) = resolve_identifier_declarator(&ident, &name, source)?;
        let key = declarator.start_byte();
        self.info.contains_key(&key).then_some(key)
    }

    fn find(&self, mut key: usize) -> usize {
        while let Some(&p) = self.parent.get(&key) {
            if p == key {
                break;
            }
            key = p;
        }
        key
    }

    fn members(&self, class: usize) -> Vec<usize> {
        self.parent
            .keys()
            .copied()
            .filter(|k| self.find(*k) == class)
            .collect()
    }

    /// Union every plain pointer copy in `body` (`q = p;`, `char *q = p;`),
    /// iterating until no class grows, so a chain of copies is one object.
    fn union_copies(&mut self, body: &Node<'a>, source: &str) {
        let pairs = assignments(body, source);
        loop {
            let mut changed = false;
            for (target, value) in &pairs {
                let v = strip_arg_casts(value);
                if v.kind() != "identifier" {
                    continue;
                }
                let (Some(a), Some(b)) = (self.of(target, source), self.of(&v, source)) else {
                    continue;
                };
                let (ra, rb) = (self.find(a), self.find(b));
                if ra != rb {
                    self.parent.insert(ra, rb);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }
}

/// Every `target = value` in `body`: assignment expressions with a plain
/// `=`, and initialized declarators (`T *target = value`), the target given
/// as the identifier node so it resolves like any other occurrence.
fn assignments<'a>(body: &Node<'a>, source: &str) -> Vec<(Node<'a>, Node<'a>)> {
    let mut out = Vec::new();
    for a in query::find_descendants_of_kind(*body, "assignment_expression") {
        let is_plain = a
            .child_by_field_name("operator")
            .is_some_and(|op| get_node_text(&op, source) == "=");
        if let (true, Some(left), Some(right)) = (
            is_plain,
            a.child_by_field_name("left"),
            a.child_by_field_name("right"),
        ) {
            out.push((left, right));
        }
    }
    for d in query::find_descendants_of_kind(*body, "init_declarator") {
        let (Some(declarator), Some(value)) = (
            d.child_by_field_name("declarator"),
            d.child_by_field_name("value"),
        ) else {
            continue;
        };
        if let Some(ident) = declarator_identifier(&declarator) {
            out.push((ident, value));
        }
    }
    out
}

/// The identifier a (possibly pointer) declarator binds.
fn declarator_identifier<'a>(declarator: &Node<'a>) -> Option<Node<'a>> {
    let mut d = *declarator;
    loop {
        match d.kind() {
            "identifier" => return Some(d),
            "pointer_declarator" | "parenthesized_declarator" => {
                d = d
                    .child_by_field_name("declarator")
                    .or_else(|| d.named_child(0))?;
            }
            _ => return None,
        }
    }
}

fn call_args<'a>(call: &Node<'a>) -> Vec<Node<'a>> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    (0..arguments.named_child_count())
        .filter_map(|i| arguments.named_child(i))
        .filter(|a| a.kind() != "comment")
        .collect()
}

fn innermost_function<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    query::find_ancestor(*node, |a| a.kind() == "function_definition")
}

/// Whether every path from `origin` to the end of its block passes `step`:
/// each block, branch or loop body enclosing `step` also encloses `origin`.
/// A `step` in an `if` condition (`if (!VirtualLock(p, n)) exit(1);`) sits
/// in no body of that `if`, so the condition always runs.
fn on_every_path_from(step: &Node, origin: &Node) -> bool {
    let mut cur = *step;
    while let Some(parent) = cur.parent() {
        if parent.kind() == "function_definition" {
            return true;
        }
        let conditional_body = match parent.kind() {
            "if_statement" | "while_statement" | "for_statement" | "do_statement" => parent
                .child_by_field_name("condition")
                .is_none_or(|c| c.id() != cur.id()),
            "compound_statement" | "case_statement" | "conditional_expression" => true,
            "binary_expression" => parent
                .child_by_field_name("left")
                .is_none_or(|l| l.id() != cur.id()),
            _ => false,
        };
        if conditional_body
            && !(parent.start_byte() <= origin.start_byte()
                && origin.end_byte() <= parent.end_byte())
        {
            return false;
        }
        cur = parent;
    }
    true
}
