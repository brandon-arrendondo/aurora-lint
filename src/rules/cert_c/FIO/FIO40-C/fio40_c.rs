// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! FIO40-C: Reset strings on fgets() or fgetws() failure
//!
//! When fgets() or fgetws() fail, the contents of the target array are
//! indeterminate, so the array must not be read again until something has
//! written it.
//!
//! ## What is reported
//!
//! A call to `fgets`/`fgetws` whose result a condition tests against NULL —
//! directly (`if (fgets(...) == NULL)`, `while (fgets(...))`, `!fgets(...)`,
//! through `&&`/`||`), assigned inside the condition
//! (`while ((p = fgets(...)) != NULL)`), or stored and tested by the next
//! statement that names the result (`p = fgets(...); if (!p) ...`) — when a
//! path leaving that condition on the failure side reaches a read of the
//! same array before anything writes it. The array is matched by
//! declaration, never by spelling (ADR-0006).
//!
//! A write ends the path: an assignment to its first element (`buf[0] =`,
//! `*buf =`), `memset`, a string copy or formatted print into it, or a
//! further read (`fgets` again). A failure branch that returns, aborts or
//! resets therefore passes — CERT's EX1 follows from the form, since a
//! buffer that is never read again is never read while indeterminate.
//! `sizeof` and a comparison of the pointer are not reads. Passing it to a
//! function is a read unless the function frees, clears or writes that
//! argument: `free` or a declared deallocator, or a body whose summary shows
//! it, never a callee's name. A pointer that holds the
//! array's address (`p = buf`, `char *p = buf`, through casts, `buf + k` and
//! `&buf[k]`) is followed along the path: a read or write through it counts
//! as one of the array, until the pointer is assigned something else.
//!
//! A call whose result is never tested is ERR33-C's construct, not this
//! rule's.
//!
//! Paths are not value-sensitive: a read guarded by a flag that only the
//! success path sets (`if (!error_flag) puts(buf);`) is still reached from
//! the failure branch, and is reported.

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::{build_function_cfg, CfgEdge, FunctionCfg};
use crate::analyze::const_eval::{self, resolve_macro_alias};
use crate::analyze::context::{ProjectContext, ScopedTable};
use crate::analyze::function_summary::FunctionSummary;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::call_roles::{frees_argument, writes_through_arg};
use crate::utility::cert_c::result_checks::same_lvalue;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tree_sitter::Node;

#[derive(Default)]
pub struct Fio40C {
    /// The driver's per-function CFGs, keyed by the function's start byte.
    function_cfgs: RefCell<HashMap<usize, FunctionCfg>>,
    /// Which parameters each function's body frees or writes.
    function_summaries: RefCell<ScopedTable<FunctionSummary>>,
    /// The project's `#define ALIAS target` table.
    macro_aliases: RefCell<Arc<HashMap<String, String>>>,
}

impl CertRule for Fio40C {
    fn rule_id(&self) -> &'static str {
        "FIO40-C"
    }

    fn description(&self) -> &'static str {
        "Reset strings on fgets() or fgetws() failure"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "FIO40-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.macro_aliases.borrow_mut() = context.macro_aliases.clone();
    }

    fn reads_header_facts(&self) -> bool {
        true
    }

    fn set_function_cfgs(&self, cfgs: &HashMap<usize, FunctionCfg>) {
        *self.function_cfgs.borrow_mut() = cfgs.clone();
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let calls = query::find_descendants(*node, |n| {
            n.kind() == "call_expression" && read_function(&n, source).is_some()
        });
        let cfgs = self.function_cfgs.borrow();
        let summaries = self.function_summaries.borrow();
        let aliases = const_eval::merged_macro_aliases(&self.macro_aliases.borrow(), node, source);
        let callees = Callees {
            summaries: &summaries,
            aliases: &aliases,
            source,
        };
        let mut built: HashMap<usize, Option<FunctionCfg>> = HashMap::new();
        for call in calls {
            let Some(func) = enclosing_function(&call) else {
                continue;
            };
            let cfg = match cfgs.get(&func.start_byte()) {
                Some(cfg) => Some(cfg),
                None => built
                    .entry(func.start_byte())
                    .or_insert_with(|| build_function_cfg(&func, source))
                    .as_ref(),
            };
            let Some(cfg) = cfg else {
                continue;
            };
            if let Some(v) = self.check_call(&call, &func, cfg, source, &callees) {
                violations.push(v);
            }
        }
    }
}

/// What one occurrence of the array does to its contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    Read,
    Write,
    Neither,
}

impl Fio40C {
    pub fn new() -> Self {
        Self::default()
    }

    fn check_call(
        &self,
        call: &Node,
        func: &Node,
        cfg: &FunctionCfg,
        source: &str,
        callees: &Callees,
    ) -> Option<RuleViolation> {
        let name = read_function(call, source)?;
        let buffer = buffer_argument(call, source)?;
        let (condition, fails_when) = failure_test(call, source)?;
        let block = cfg
            .blocks
            .iter()
            .find(|b| b.condition_range == Some((condition.start_byte(), condition.end_byte())))?;
        let is_do = condition
            .parent()
            .is_some_and(|p| p.kind() == "do_statement");
        let failure_edge = |e: &CfgEdge| {
            if fails_when {
                *e == CfgEdge::TrueBranch || (is_do && *e == CfgEdge::BackEdge)
            } else {
                *e == CfgEdge::FalseBranch
            }
        };
        let starts: Vec<usize> = cfg
            .successors(block.id)
            .into_iter()
            .filter(|(_, e)| failure_edge(e))
            .map(|(b, _)| b)
            .collect();
        if starts.is_empty() {
            return None;
        }

        let body = func.child_by_field_name("body")?;
        let events = path_events(&body, &buffer, source, callees);
        let initial = aliases_held_at(&events, call.start_byte());

        let read = first_read_on_failure_path(cfg, &starts, &events, initial)?;
        let at = call.start_position();
        let buffer_text = get_node_text(&buffer, source);
        Some(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::Low,
            message: format!(
                "'{}' is read at line {} on a path where {}() failed, before anything \
                 writes it - its contents are indeterminate after a failed read",
                buffer_text,
                read.start_position().row + 1,
                name
            ),
            file_path: String::new(),
            line: at.row + 1,
            column: at.column + 1,
            suggestion: Some(format!(
                "Reset the buffer when {}() returns NULL ('{}[0] = {}\\0';'), or leave \
                 the function without reading it",
                name,
                buffer_text,
                if name == "fgetws" { "L'" } else { "'" }
            )),
            ..Default::default()
        })
    }
}

/// `fgets` or `fgetws` when `call` calls one of them by name.
fn read_function<'s>(call: &Node, source: &'s str) -> Option<&'s str> {
    let f = call.child_by_field_name("function")?;
    let name = get_node_text(&f, source);
    matches!(name, "fgets" | "fgetws").then_some(name)
}

fn enclosing_function<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        if n.kind() == "function_definition" {
            return Some(n);
        }
        cur = n.parent();
    }
    None
}

/// The array the call reads into: its first argument with parentheses and
/// casts peeled, and `&a[0]` read as `a`. Only an object designator (a name
/// or a member) can be followed.
fn buffer_argument<'a>(call: &Node<'a>, source: &str) -> Option<Node<'a>> {
    let args = call.child_by_field_name("arguments")?;
    let mut arg = peel(args.named_child(0)?);
    if arg.kind() == "pointer_expression" && arg.child(0).is_some_and(|o| o.kind() == "&") {
        let inner = peel(arg.child_by_field_name("argument")?);
        if inner.kind() == "subscript_expression"
            && inner
                .child_by_field_name("index")
                .is_some_and(|i| get_node_text(&i, source).trim() == "0")
        {
            arg = peel(inner.child_by_field_name("argument")?);
        }
    }
    matches!(arg.kind(), "identifier" | "field_expression").then_some(arg)
}

fn peel(mut n: Node) -> Node {
    while matches!(n.kind(), "parenthesized_expression" | "cast_expression") {
        let inner = if n.kind() == "cast_expression" {
            n.child_by_field_name("value")
        } else {
            n.named_child(0)
        };
        match inner {
            Some(i) => n = i,
            None => break,
        }
    }
    n
}

/// The controlling condition that tests the call's result for NULL, and the
/// value that condition takes when the call failed. Follows the result
/// through parentheses, casts, `!`, `== NULL`/`!= NULL`, an assignment's
/// value, and the side of `&&`/`||` the failure decides; then, when the
/// result was stored, the next statement that names the variable.
fn failure_test<'a>(call: &Node<'a>, source: &str) -> Option<(Node<'a>, bool)> {
    match follow_result(*call, false, source)? {
        Followed::Condition(c, v) => Some((c, v)),
        Followed::Stored(stmt, target) => stored_result_test(&stmt, &target, source),
    }
}

enum Followed<'a> {
    /// The controlling condition reached, with its value on failure.
    Condition(Node<'a>, bool),
    /// The result stored into `target` by the statement `stmt`.
    Stored(Node<'a>, Node<'a>),
}

/// Climb from `node`, whose truth value on failure is `truth`.
fn follow_result<'a>(mut node: Node<'a>, mut truth: bool, source: &str) -> Option<Followed<'a>> {
    loop {
        let parent = node.parent()?;
        match parent.kind() {
            "parenthesized_expression" => {
                if let Some(owner) = parent.parent() {
                    if matches!(
                        owner.kind(),
                        "if_statement" | "while_statement" | "do_statement"
                    ) && owner.child_by_field_name("condition") == Some(parent)
                    {
                        return Some(Followed::Condition(parent, truth));
                    }
                }
            }
            "cast_expression" => {}
            "assignment_expression" => {
                let is_value = parent.child_by_field_name("right") == Some(node)
                    && parent
                        .child_by_field_name("operator")
                        .is_some_and(|o| o.kind() == "=");
                if !is_value {
                    return None;
                }
                let target = parent.child_by_field_name("left")?;
                if parent
                    .parent()
                    .is_some_and(|s| s.kind() == "expression_statement")
                {
                    return Some(Followed::Stored(parent.parent()?, target));
                }
            }
            "init_declarator" => {
                if parent.child_by_field_name("value") != Some(node) {
                    return None;
                }
                let mut target = parent.child_by_field_name("declarator")?;
                while let Some(inner) = target.child_by_field_name("declarator") {
                    target = inner;
                }
                let stmt = parent.parent().filter(|d| d.kind() == "declaration")?;
                return Some(Followed::Stored(stmt, target));
            }
            "unary_expression" => {
                if parent.child(0).is_none_or(|o| o.kind() != "!") {
                    return None;
                }
                truth = !truth;
            }
            "binary_expression" => {
                let op = parent.child_by_field_name("operator")?;
                match op.kind() {
                    "==" | "!=" => {
                        let left = parent.child_by_field_name("left")?;
                        let right = parent.child_by_field_name("right")?;
                        let other = if left == node { right } else { left };
                        if !is_null_constant(&other, source) {
                            return None;
                        }
                        // The pointer is null on failure: `== NULL` is then
                        // true, `!= NULL` false.
                        truth = if op.kind() == "==" { !truth } else { truth };
                    }
                    // Only the side that decides the whole is followed: a false
                    // conjunct makes `&&` false, a true disjunct makes `||` true.
                    "&&" if !truth => {}
                    "||" if truth => {}
                    _ => return None,
                }
            }
            "for_statement" => {
                return (parent.child_by_field_name("condition") == Some(node))
                    .then_some(Followed::Condition(node, truth));
            }
            _ => return None,
        }
        node = parent;
    }
}

/// `p = fgets(...); if (!p) ...`: the next statement in the same block that
/// names `target` must be a loop or `if` whose condition tests it.
fn stored_result_test<'a>(
    stmt: &Node<'a>,
    target: &Node<'a>,
    source: &str,
) -> Option<(Node<'a>, bool)> {
    let mut next = stmt.next_named_sibling();
    while let Some(s) = next {
        let mentions: Vec<Node> = occurrences(&s, target, source);
        if mentions.is_empty() {
            next = s.next_named_sibling();
            continue;
        }
        if !matches!(
            s.kind(),
            "if_statement" | "while_statement" | "do_statement" | "for_statement"
        ) {
            return None;
        }
        let condition = s.child_by_field_name("condition")?;
        return occurrences(&condition, target, source)
            .into_iter()
            .find_map(|o| match follow_result(o, false, source)? {
                Followed::Condition(c, v) if c == condition => Some((c, v)),
                _ => None,
            });
    }
    None
}

fn is_null_constant(n: &Node, source: &str) -> bool {
    let n = peel(*n);
    matches!(
        get_node_text(&n, source).trim(),
        "NULL" | "0" | "0L" | "nullptr"
    )
}

/// Every occurrence under `root` that designates the same object as `target`,
/// declarators excluded.
fn occurrences<'a>(root: &Node<'a>, target: &Node, source: &str) -> Vec<Node<'a>> {
    let kind = target.kind();
    let name = last_name(target, source);
    query::find_descendants(*root, |n| {
        n.kind() == kind
            && last_name(&n, source) == name
            && !is_declarator(&n)
            && same_lvalue(&n, target, source)
    })
}

/// The identifier a name or member access ends in: `buf`, or `line` for
/// `s->line`.
fn last_name<'s>(n: &Node, source: &'s str) -> &'s str {
    match n.kind() {
        "field_expression" => n
            .child_by_field_name("field")
            .map_or("", |f| get_node_text(&f, source)),
        _ => get_node_text(n, source),
    }
}

fn is_declarator(n: &Node) -> bool {
    n.parent().is_some_and(|p| {
        if p.kind() == "init_declarator" {
            // The name declared, not the initializer's value.
            return p.child_by_field_name("declarator") == Some(*n);
        }
        p.kind().ends_with("_declarator")
            || matches!(p.kind(), "declaration" | "parameter_declaration")
    })
}

/// Whether one occurrence of the array reads its contents, writes them, or
/// does neither.
fn classify(occ: Node, source: &str, callees: &Callees) -> Access {
    let mut v = occ;
    loop {
        let Some(p) = v.parent() else {
            return Access::Read;
        };
        match p.kind() {
            "parenthesized_expression" | "cast_expression" | "conditional_expression" => {
                if p.kind() == "conditional_expression"
                    && p.child_by_field_name("condition") == Some(v)
                {
                    return Access::Neither;
                }
                v = p;
            }
            "sizeof_expression" | "alignof_expression" | "offsetof_expression" => {
                return Access::Neither
            }
            "subscript_expression" if p.child_by_field_name("argument") == Some(v) => {
                let zero = p
                    .child_by_field_name("index")
                    .is_some_and(|i| get_node_text(&i, source).trim() == "0");
                return classify_element(p, zero, source, callees);
            }
            "pointer_expression" => {
                if p.child(0).is_some_and(|o| o.kind() == "*") {
                    return classify_element(p, true, source, callees);
                }
                // `&buf`: the address, used as the array itself is.
                v = p;
            }
            "binary_expression" => {
                let op = p.child_by_field_name("operator").map(|o| o.kind());
                match op {
                    // Pointer arithmetic: the result points into the array.
                    Some("+") | Some("-") => v = p,
                    // Comparing the pointer or testing it reads no contents.
                    _ => return Access::Neither,
                }
            }
            "unary_expression" | "update_expression" => return Access::Neither,
            "argument_list" => return classify_argument(&p, &v, source, callees),
            "assignment_expression" => {
                return if p.child_by_field_name("left") == Some(v) {
                    // The pointer itself replaced: the old contents are gone
                    // from this name.
                    Access::Write
                } else {
                    Access::Neither
                };
            }
            "init_declarator" => return Access::Neither,
            "if_statement" | "while_statement" | "do_statement" | "for_statement" => {
                return Access::Neither
            }
            _ => return Access::Read,
        }
    }
}

/// `buf[k]` or `*buf`: a store into the first element resets the string; any
/// other store leaves it as indeterminate as before; a load reads it.
fn classify_element(element: Node, first: bool, source: &str, callees: &Callees) -> Access {
    let mut e = element;
    while let Some(p) = e.parent() {
        match p.kind() {
            "parenthesized_expression" => e = p,
            "sizeof_expression" | "alignof_expression" => return Access::Neither,
            "pointer_expression" if p.child(0).is_some_and(|o| o.kind() == "&") => {
                // `&buf[k]`: a pointer into the array.
                return classify(p, source, callees);
            }
            "assignment_expression" if p.child_by_field_name("left") == Some(e) => {
                let plain = p
                    .child_by_field_name("operator")
                    .is_some_and(|o| o.kind() == "=");
                return match (plain, first) {
                    (true, true) => Access::Write,
                    (true, false) => Access::Neither,
                    (false, _) => Access::Read,
                };
            }
            _ => return Access::Read,
        }
    }
    Access::Read
}

/// The array passed to a call: written by a function that only stores
/// into that argument, read otherwise (a concatenation reads its
/// destination first).
fn classify_argument(args: &Node, arg: &Node, source: &str, callees: &Callees) -> Access {
    let Some(call) = args.parent() else {
        return Access::Read;
    };
    let Some(callee) = call.child_by_field_name("function") else {
        return Access::Read;
    };
    let spelled = get_node_text(&callee, source);
    let name = resolve_macro_alias(callees.aliases, spelled);
    let Some(idx) = (0..args.named_child_count()).find(|&i| args.named_child(i) == Some(*arg))
    else {
        return Access::Read;
    };
    if matches!(
        name,
        "strcat" | "strncat" | "strlcat" | "wcscat" | "wcsncat"
    ) {
        return Access::Read;
    }
    if matches!(name, "memset" | "wmemset") && idx == 0 {
        return Access::Write;
    }
    if writes_through_arg(name, idx) || callees.ends(name, idx, call.start_position().row + 1) {
        Access::Write
    } else {
        Access::Read
    }
}

/// What the scan knows about the functions a call may reach: a call that
/// frees the array or writes through it ends its indeterminate contents
/// as surely as a store does. Known only by proof: `free`, a declared
/// deallocator, or a body whose summary frees, clears or writes that
/// parameter -- never by a callee's name.
pub(crate) struct Callees<'c> {
    summaries: &'c ScopedTable<FunctionSummary>,
    aliases: &'c HashMap<String, String>,
    source: &'c str,
}

impl Callees<'_> {
    fn ends(&self, name: &str, idx: usize, line: usize) -> bool {
        if frees_argument(name) == Some(idx) {
            return true;
        }
        self.summaries.get(name).is_some_and(|s| {
            let s = s.at(self.source, line);
            s.frees_params.contains(&idx)
                || s.modifies_params.contains(&idx)
                || s.clears_params.contains(&idx)
        })
    }
}

/// Something on a path that bears on the array: an access to it, a pointer
/// starting or ceasing to hold its address, or an access through such a
/// pointer (effective only while it holds the address).
#[derive(Clone, Copy)]
enum Event<'a> {
    Array(Access, Node<'a>),
    AliasOn(usize),
    AliasOff(usize),
    Alias(usize, Access, Node<'a>),
}

/// At most this many pointers are followed as aliases of one array.
const MAX_ALIASES: usize = 64;

/// Every event in the function body, in source order.
fn path_events<'a>(
    body: &Node<'a>,
    buffer: &Node<'a>,
    source: &str,
    callees: &Callees,
) -> Vec<(usize, Event<'a>)> {
    let mut aliases: Vec<Node<'a>> = Vec::new();
    let mut events = Vec::new();
    for occ in occurrences(body, buffer, source) {
        if let Some(target) = alias_target(occ) {
            let i = match aliases.iter().position(|a| same_lvalue(a, &target, source)) {
                Some(i) => i,
                None if aliases.len() < MAX_ALIASES => {
                    aliases.push(target);
                    aliases.len() - 1
                }
                None => continue,
            };
            events.push((occ.start_byte(), Event::AliasOn(i)));
            continue;
        }
        let access = classify(occ, source, callees);
        if access != Access::Neither {
            events.push((occ.start_byte(), Event::Array(access, occ)));
        }
    }
    for (i, alias) in aliases.iter().enumerate() {
        for occ in occurrences(body, alias, source) {
            let Some(parent) = occ.parent() else {
                continue;
            };
            if parent.kind() == "assignment_expression"
                && parent.child_by_field_name("left") == Some(occ)
            {
                let plain = parent
                    .child_by_field_name("operator")
                    .is_some_and(|o| o.kind() == "=");
                let from_array = parent.child_by_field_name("right").is_some_and(|r| {
                    !occurrences(&r, buffer, source).is_empty()
                        || occurrences_at(&r, buffer, source)
                });
                if plain && !from_array {
                    events.push((occ.start_byte(), Event::AliasOff(i)));
                }
                continue;
            }
            if parent.kind() == "update_expression" {
                continue;
            }
            let access = classify(occ, source, callees);
            if access != Access::Neither {
                events.push((occ.start_byte(), Event::Alias(i, access, occ)));
            }
        }
    }
    events.sort_by_key(|(at, _)| *at);
    events
}

/// `r` is itself the array (`p = buf;`), which `occurrences` under `r` does
/// not see.
fn occurrences_at(r: &Node, buffer: &Node, source: &str) -> bool {
    let r = peel(*r);
    r.kind() == buffer.kind() && same_lvalue(&r, buffer, source)
}

/// The pointer an occurrence of the array is stored into, when it is:
/// `p = buf`, `char *p = buf`, through casts, `buf + k` and `&buf[k]`.
fn alias_target<'a>(occ: Node<'a>) -> Option<Node<'a>> {
    let mut v = occ;
    loop {
        let p = v.parent()?;
        match p.kind() {
            "parenthesized_expression" | "cast_expression" => v = p,
            "binary_expression"
                if p.child_by_field_name("operator")
                    .is_some_and(|o| matches!(o.kind(), "+" | "-")) =>
            {
                v = p
            }
            "pointer_expression" if p.child(0).is_some_and(|o| o.kind() == "&") => v = p,
            "subscript_expression" if p.child_by_field_name("argument") == Some(v) => {
                let amp = p.parent()?;
                if amp.kind() == "pointer_expression"
                    && amp.child(0).is_some_and(|o| o.kind() == "&")
                {
                    v = amp;
                } else {
                    return None;
                }
            }
            "assignment_expression" => {
                let plain = p
                    .child_by_field_name("operator")
                    .is_some_and(|o| o.kind() == "=");
                if !plain || p.child_by_field_name("right") != Some(v) {
                    return None;
                }
                let left = peel(p.child_by_field_name("left")?);
                return (left.kind() == "identifier").then_some(left);
            }
            "init_declarator" => {
                if p.child_by_field_name("value") != Some(v) {
                    return None;
                }
                let mut d = p.child_by_field_name("declarator")?;
                while let Some(inner) = d.child_by_field_name("declarator") {
                    d = inner;
                }
                return (d.kind() == "identifier").then_some(d);
            }
            _ => return None,
        }
    }
}

/// The aliases holding the array's address when the call runs, read in
/// source order: each one whose last event before `at` started it.
fn aliases_held_at(events: &[(usize, Event)], at: usize) -> u64 {
    let mut mask = 0u64;
    for (pos, e) in events {
        if *pos >= at {
            break;
        }
        match e {
            Event::AliasOn(i) => mask |= 1 << i,
            Event::AliasOff(i) => mask &= !(1 << i),
            _ => {}
        }
    }
    mask
}

/// Breadth-first over the CFG from the failure successors, carrying which
/// aliases hold the array's address: the first read of the array, directly
/// or through a holding alias, met on some path before a write.
fn first_read_on_failure_path<'a>(
    cfg: &FunctionCfg,
    starts: &[usize],
    events: &[(usize, Event<'a>)],
    initial: u64,
) -> Option<Node<'a>> {
    let mut seen: HashSet<(usize, u64)> = HashSet::new();
    let mut queue: VecDeque<(usize, u64)> = starts.iter().map(|&b| (b, initial)).collect();
    'blocks: while let Some((id, mut mask)) = queue.pop_front() {
        if !seen.insert((id, mask)) {
            continue;
        }
        let Some(block) = cfg.get_block(id) else {
            continue;
        };
        let in_block = events
            .iter()
            .filter(|(at, _)| block.statements.iter().any(|&(s, e)| *at >= s && *at < e));
        for (_, e) in in_block {
            let access = match *e {
                Event::Array(a, n) => Some((a, n)),
                Event::Alias(i, a, n) if mask & (1 << i) != 0 => Some((a, n)),
                Event::AliasOn(i) => {
                    mask |= 1 << i;
                    None
                }
                Event::AliasOff(i) => {
                    mask &= !(1 << i);
                    None
                }
                Event::Alias(..) => None,
            };
            match access {
                Some((Access::Read, n)) => return Some(n),
                Some((Access::Write, _)) => continue 'blocks,
                _ => {}
            }
        }
        queue.extend(cfg.successors(id).into_iter().map(|(b, _)| (b, mask)));
    }
    None
}
