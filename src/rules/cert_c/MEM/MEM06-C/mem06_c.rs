// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! MEM06-C: Ensure that sensitive data is not written out to disk
//!
//! A buffer is sensitive when it reaches a declared credential sink
//! (`credential_sinks::CREDENTIAL_SINKS`: `LogonUser`'s password, `crypt`'s
//! key, a `PAM_AUTHTOK` item, a database login's password), directly or
//! through a function whose summary says it forwards that parameter to one.
//! That is the rule's checkable form and the Juliet CWE-591 definition; a
//! name like `secret` proves nothing.
//!
//! Each allocation in a function (a heap or Win32 allocator, a project
//! source whose summary returns an allocation, or a local array) is followed
//! forward in source order through plain copies and pointer offsets
//! (`q = p`, `char *q = p + 1`), each variable resolved by declaration: a
//! later overwrite of a copy ends it. The allocation is sensitive when a
//! variable holding it reaches a sink, and it is protected when
//! - a page lock (`mlock`, `VirtualLock`, `sodium_mlock`, or a project
//!   function whose summary locks that argument) of a holder runs on every
//!   path to each store into the buffer, or to the sink if nothing is
//!   stored first; a lock after the secret was written leaves the pages it
//!   sat in unprotected, and a lock in one arm does not cover a store in
//!   another;
//! - the allocator hands the block back locked (`sodium_malloc`, a project
//!   source whose summary says `returns_locked`); or
//! - process-wide protection (a zero `RLIMIT_CORE`, `mlockall`) runs on
//!   every path to that point in the same function, or in `main` before the
//!   first call that leads to this function, when every call from `main`
//!   that leads here comes after it.
//!
//! The finding is reported where the unprotected block is released, or at
//! the sink when this function does not release it; the allocation is named
//! in the message (ADR-0012). A buffer that arrives as a parameter is judged
//! where it was allocated, not where it is used.
//!
//! Not traced (false negatives): a copy through memory (`*pp = p`, a struct
//! field, a union, an array element), a call through a function pointer, and
//! a global the allocation is handed over in.
//!
//! Not credited (reported although protected): protection that `main`
//! reaches only inside the same call that leads here
//! (`main -> run() { setrlimit(...); login(); }`), since only the calls
//! `main` makes after its own protecting call count.
//!
//! "Runs before on every path" is `runs_before_on_every_path` over the AST,
//! and where that walk says no (a `goto`, a `break` out of a `do` body, a
//! lock in another arm) the function's CFG answers exactly, so a lock that
//! Juliet reaches through `goto` still counts.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::{build_function_cfg, FunctionCfg};
use crate::analyze::const_eval::resolve_macro_alias;
use crate::analyze::context::{ProjectContext, ScopedTable};
use crate::analyze::function_summary::{
    sets_zero_core_limit, FunctionSummary, PROTECTS_PROCESS_MARKER,
};
use crate::analyze::init_state::strip_arg_casts;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{
    get_identifier_from_declarator, get_node_text, resolve_identifier_declarator,
};
use crate::utility::cert_c::guard_dominance::{
    in_expression_branch_outside, preproc_choices_outside, runs_before_on_every_path, PreprocChoice,
};
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

    fn cert_id(&self) -> &'static str {
        "MEM06-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.call_graph.borrow_mut() = context.call_graph.clone();
        *self.macro_aliases.borrow_mut() = context.macro_aliases.clone();
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut program: Option<ProgramProtection> = None;
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function(&func, source, &mut program, violations);
        }
    }
}

/// Where a block comes from.
struct Origin<'a> {
    /// The allocating call, or the array's declarator.
    node: Node<'a>,
    /// Where the block starts being held: the assignment or declaration.
    at: usize,
    /// The object that first holds it.
    holder: usize,
    /// How to name it in the message.
    what: String,
    /// The allocator hands the block back locked.
    locked: bool,
    /// A local array whose initializer already writes data into it.
    initialized: bool,
}

/// One copy or overwrite of a variable, in source order.
struct Copy<'a> {
    node: Node<'a>,
    at: usize,
    target: usize,
    source: Option<usize>,
}

/// Which functions a program's `main` reaches only after process-wide
/// protection has run. Computed once per file.
#[derive(Default)]
struct ProgramProtection {
    protected: HashSet<String>,
    unprotected: HashSet<String>,
}

impl Mem06C {
    fn check_function(
        &self,
        func: &Node,
        source: &str,
        program: &mut Option<ProgramProtection>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(body) = func.child_by_field_name("body") else {
            return;
        };
        let calls: Vec<Node> = query::find_descendants_of_kind(body, "call_expression")
            .into_iter()
            .filter(|c| innermost_function(c).is_some_and(|f| f.id() == func.id()))
            .collect();

        // Every argument that receives a secret, as (call, callee, object).
        let mut sinks: Vec<(Node, String, usize)> = Vec::new();
        for call in &calls {
            let Some(callee) = self.callee_name(call, source) else {
                continue;
            };
            let args = call_args(call);
            for idx in self.sink_arg_indices(&callee, &args, source) {
                if let Some(object) = args.get(idx).and_then(|a| object_of(a, source)) {
                    sinks.push((*call, callee.clone(), object));
                }
            }
        }
        if sinks.is_empty() {
            return;
        }

        let copies = copies_in(&body, source);
        let cfg: std::cell::OnceCell<Option<FunctionCfg>> = std::cell::OnceCell::new();
        // The CFG settles what the AST walk refuses over jumps; it cannot
        // see a `&&`/`||`/`?:` branch, so it is never asked about a step in
        // one.
        let precedes = |step: &Node, target: &Node| {
            runs_before_on_every_path(step, target)
                || !in_expression_branch_outside(step, target)
                    && cfg
                        .get_or_init(|| build_function_cfg(func, source))
                        .as_ref()
                        .is_some_and(|g| cfg_dominates(g, step, target))
        };
        let mut reported: HashSet<usize> = HashSet::new();
        for origin in self.origins(&body, source) {
            let holds = |object: usize, site: &Node| {
                holders_at(&origin, &copies, site, &precedes).contains(&object)
            };
            let Some((first_sink, sink_callee, sink_object)) = sinks
                .iter()
                .filter(|(call, _, object)| call.start_byte() > origin.at && holds(*object, call))
                .min_by_key(|(call, _, _)| call.start_byte())
            else {
                continue;
            };
            if origin.locked {
                continue;
            }
            let bounds = if origin.initialized {
                vec![origin.node]
            } else {
                // A store on a path that leaves before any sink never puts
                // the secret there: `if (m) { strcpy(p, "x"); return; }`.
                let origin_sinks: Vec<&Node> = sinks
                    .iter()
                    .filter(|(call, _, object)| {
                        call.start_byte() > origin.at && holds(*object, call)
                    })
                    .map(|(call, _, _)| call)
                    .collect();
                let graph = cfg
                    .get_or_init(|| build_function_cfg(func, source))
                    .as_ref();
                let mut stores = self.stores(
                    &calls, &body, &origin, &copies, first_sink, source, &precedes,
                );
                if let Some(g) = graph {
                    stores.retain(|s| origin_sinks.iter().any(|k| cfg_reaches(g, s, k)));
                }
                if stores.is_empty() {
                    stores.push(*first_sink);
                }
                stores
            };
            // Every store must be covered: a lock on one arm does not protect
            // the secret another arm writes unlocked. Either kind of cover
            // will do for each store -- one arm may lock the block while the
            // other protects the whole process.
            let is_lock = |call: &Node| {
                call.start_byte() > origin.at && self.is_lock_of(call, source, |o| holds(o, call))
            };
            let covered = bounds.iter().all(|bound| {
                calls.iter().any(|call| {
                    is_lock(call)
                        && precedes(call, bound)
                        && in_every_configuration(call, bound, &calls, source, &is_lock, &precedes)
                }) || self.protected_locally(&calls, bound, source, &precedes)
            });
            if covered || self.protected_by_program(func, source, program) {
                continue;
            }

            let release = calls
                .iter()
                .filter(|c| c.start_byte() > first_sink.start_byte())
                .filter(|c| self.released_object(c, source).is_some_and(|o| holds(o, c)))
                .max_by_key(|c| c.start_byte());
            let site = release.unwrap_or(first_sink);
            if !reported.insert(site.start_byte()) {
                continue;
            }
            let var = object_name(first_sink, *sink_object, source);
            let origin_line = origin.node.start_position().row + 1;
            let sink_line = first_sink.start_position().row + 1;
            let message = if release.is_some() {
                format!(
                    "'{var}' holds a credential (passed to {sink_callee} at line {sink_line}) and \
                     is released here, but no page lock of it runs before the secret is stored: \
                     {} at line {origin_line} may be written to swap or a core dump.",
                    origin.what
                )
            } else {
                format!(
                    "'{var}' reaches a credential sink ({sink_callee}), but no page lock of it \
                     runs before the secret is stored: {} at line {origin_line} may be written \
                     to swap or a core dump.",
                    origin.what
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
                     the secret is stored in it, allocate it with a locking allocator, or \
                     disable core dumps with setrlimit(RLIMIT_CORE) set to zero at startup."
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
        let resolved = resolve_macro_alias(&aliases, name);
        if resolved != name && !self.function_summaries.borrow().contains_key(name) {
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

    /// Whether `call` locks the pages of an object `held` accepts.
    fn is_lock_of(&self, call: &Node, source: &str, held: impl Fn(usize) -> bool) -> bool {
        let Some(callee) = self.callee_name(call, source) else {
            return false;
        };
        let indices: Vec<usize> = match self.function_summaries.borrow().get(&callee) {
            Some(s) => s.locks_params.iter().copied().collect(),
            None if credential_sinks::is_page_lock_call(&callee) => vec![0],
            None => Vec::new(),
        };
        let args = call_args(call);
        indices.iter().any(|&i| {
            args.get(i)
                .and_then(|a| object_of(a, source))
                .is_some_and(&held)
        })
    }

    /// The object a release call frees: a library deallocator's argument, or
    /// a parameter a project deallocator's summary frees.
    fn released_object(&self, call: &Node, source: &str) -> Option<usize> {
        let callee = self.callee_name(call, source)?;
        let args = call_args(call);
        let idx = match self.function_summaries.borrow().get(&callee) {
            Some(s) => s.frees_params.iter().copied().min()?,
            None => credential_sinks::released_arg(&callee)?,
        };
        object_of(args.get(idx)?, source)
    }

    /// Every block this body allocates: assignments from an allocating call,
    /// and local arrays.
    fn origins<'a>(&self, body: &Node<'a>, source: &str) -> Vec<Origin<'a>> {
        let summaries = self.function_summaries.borrow();
        let mut out = Vec::new();
        for (assignment, target, value) in assignments(body, source) {
            let at = assignment.start_byte();
            let value = strip_arg_casts(&value);
            if value.kind() != "call_expression" {
                continue;
            }
            let Some(callee) = self.callee_name(&value, source) else {
                continue;
            };
            let Some(holder) = object_key(&target, source) else {
                continue;
            };
            let locked = match summaries.get(&callee) {
                Some(s) if s.returns_allocation || s.returns_locked => s.returns_locked,
                Some(_) => continue,
                None => match credential_sinks::platform_allocation_is_locked(&callee) {
                    Some(locked) => locked,
                    None if call_roles::is_allocator_call(&callee) => false,
                    None => continue,
                },
            };
            out.push(Origin {
                node: value,
                at,
                holder,
                what: format!("the block from {callee}()"),
                locked,
                initialized: false,
            });
        }
        for declarator in query::find_descendants_of_kind(*body, "array_declarator") {
            let Some(decl) = declarator.parent() else {
                continue;
            };
            let (decl_node, init) = match decl.kind() {
                "init_declarator" => (decl.parent(), decl.child_by_field_name("value")),
                "declaration" => (Some(decl), None),
                _ => continue,
            };
            if decl_node.is_none_or(|d| d.kind() != "declaration") {
                continue;
            }
            let name = get_identifier_from_declarator(&declarator, source);
            if name.is_empty() {
                continue;
            }
            out.push(Origin {
                node: declarator,
                at: declarator.start_byte(),
                holder: declarator.start_byte(),
                what: format!("the array '{name}'"),
                locked: false,
                initialized: init.is_some_and(|v| writes_data(&v, source)),
            });
        }
        out
    }

    /// Every store into the block between its allocation and the sink, or
    /// just the sink when nothing is stored first. A store writes data through a holder: a
    /// library call that writes through that argument (`strcpy`'s
    /// destination, `fgets`'s buffer, a non-zero `memset` fill), a project
    /// function whose summary writes through that parameter, or an
    /// assignment through one (`p[i] = c`, `*(p + i) = c`). A call that only
    /// takes the address (`madvise`, a `%p` log line, a validator) stores
    /// nothing, and neither does a lock or a zeroing clear.
    fn stores<'a>(
        &self,
        calls: &[Node<'a>],
        body: &Node<'a>,
        origin: &Origin,
        copies: &[Copy],
        sink: &Node<'a>,
        source: &str,
        precedes: &dyn Fn(&Node, &Node) -> bool,
    ) -> Vec<Node<'a>> {
        let holds = |object: usize, site: &Node| {
            holders_at(origin, copies, site, precedes).contains(&object)
        };
        let summaries = self.function_summaries.borrow();
        let call_stores = calls
            .iter()
            .filter(|c| c.start_byte() > origin.at && c.start_byte() < sink.start_byte())
            .filter(|c| {
                let Some(callee) = self.callee_name(c, source) else {
                    return false;
                };
                let args = call_args(c);
                let writes = |i: usize| match summaries.get(&callee) {
                    Some(s) => s.modifies_params.contains(&i),
                    None => {
                        call_roles::writes_through_arg(&callee, i)
                            || (i == 0 && is_data_fill(&args, source, &callee))
                    }
                };
                // `getline(&line, ...)` writes into the block `line` points at.
                let pointee = |i: usize, a: &Node| {
                    !summaries.contains_key(&callee)
                        && call_roles::writes_through_pointee_of_arg(&callee, i)
                        && address_of(a)
                            .and_then(|p| object_key(&p, source))
                            .is_some_and(|o| holds(o, c))
                };
                args.iter().enumerate().any(|(i, a)| {
                    (writes(i) && object_of(a, source).is_some_and(|o| holds(o, c)))
                        || pointee(i, a)
                })
            })
            .copied();
        let write_stores = query::find_descendants_of_kind(*body, "assignment_expression")
            .into_iter()
            .filter(|a| a.start_byte() > origin.at && a.start_byte() < sink.start_byte())
            .filter(|a| {
                a.child_by_field_name("left")
                    .and_then(|l| written_through(&l))
                    .and_then(|b| object_of(&b, source))
                    .is_some_and(|o| holds(o, a))
            });
        let mut stores: Vec<Node<'a>> = call_stores.chain(write_stores).collect();
        if stores.is_empty() {
            stores.push(*sink);
        }
        stores
    }

    /// Process-wide protection in this function on every path to `bound`:
    /// a zero `RLIMIT_CORE`, `mlockall`, or a call to a function whose
    /// summary protects the process.
    fn protected_locally(
        &self,
        calls: &[Node],
        bound: &Node,
        source: &str,
        precedes: &dyn Fn(&Node, &Node) -> bool,
    ) -> bool {
        let protects = |call: &Node| {
            let Some(callee) = self.callee_name(call, source) else {
                return false;
            };
            if let Some(s) = self.function_summaries.borrow().get(&callee) {
                return s.protects_process_memory;
            }
            callee == "mlockall"
                || (callee == "setrlimit" && sets_zero_core_limit(call, &call_args(call), source))
        };
        calls.iter().any(|call| {
            precedes(call, bound)
                && protects(call)
                && in_every_configuration(call, bound, calls, source, &protects, precedes)
        })
    }

    /// Whether `main` protects the process before its first call that leads
    /// to `func`, and never reaches `func` before that.
    fn protected_by_program(
        &self,
        func: &Node,
        source: &str,
        program: &mut Option<ProgramProtection>,
    ) -> bool {
        let Some(name) = function_name(func, source) else {
            return false;
        };
        if name == "main" {
            return false;
        }
        let program = program.get_or_insert_with(|| self.program_protection());
        program.protected.contains(&name) && !program.unprotected.contains(&name)
    }

    fn program_protection(&self) -> ProgramProtection {
        let summaries = self.function_summaries.borrow();
        let Some(main) = summaries.get("main") else {
            return ProgramProtection::default();
        };
        if main.main_call_sequence_ambiguous {
            return ProgramProtection::default();
        }
        let sequence = &main.main_call_sequence;
        let protects = |callee: &str| {
            callee == PROTECTS_PROCESS_MARKER
                || summaries
                    .get(callee)
                    .is_some_and(|s| s.protects_process_memory)
        };
        let Some(point) = sequence
            .iter()
            .position(|(callee, unconditional)| *unconditional && protects(callee))
        else {
            return ProgramProtection::default();
        };
        let graph = self.call_graph.borrow();
        let reach = |roots: &[(String, bool)]| -> HashSet<String> {
            let mut seen: HashSet<String> = HashSet::new();
            let mut queue: VecDeque<String> = roots.iter().map(|(c, _)| c.clone()).collect();
            while let Some(f) = queue.pop_front() {
                if !seen.insert(f.clone()) {
                    continue;
                }
                if let Some(callees) = graph.get(&f) {
                    queue.extend(callees.iter().cloned());
                }
            }
            seen
        };
        ProgramProtection {
            protected: reach(&sequence[point + 1..]),
            unprotected: reach(&sequence[..point]),
        }
    }
}

/// Whether the guarantee `step` gives `bound` holds in every build
/// configuration (ADR-0010): for each `#if` chain that compiles `step` but
/// not necessarily `bound`, every configuration compiles one of its arms
/// (an `#else`, or an `#if 1`), and every live arm holds a call that
/// `is_guard` accepts, that precedes `bound`, and whose own guarantee holds
/// in every configuration of the chains nested inside that arm. So
/// `#ifdef _WIN32 VirtualLock(..) #else mlock(..) #endif` covers the store,
/// while an `#ifdef USE_MLOCK` with no `#else`, or an `#else` whose `mlock`
/// sits under an inner `#ifdef HAVE_MLOCK`, leaves a build unprotected. An
/// arm only a literal condition rules out (`#if 0`) is no configuration.
fn in_every_configuration(
    step: &Node,
    bound: &Node,
    calls: &[Node],
    source: &str,
    is_guard: &dyn Fn(&Node) -> bool,
    precedes: &dyn Fn(&Node, &Node) -> bool,
) -> bool {
    let choices = preproc_choices_outside(step, bound, source);
    if choices.is_empty() {
        return true;
    }
    let memo = RefCell::new(HashMap::new());
    covered_within(
        &choices, None, bound, calls, source, is_guard, precedes, &memo,
    )
}

/// `covered_within`'s answers, keyed by (guard start byte, arm range).
type ArmMemo = RefCell<HashMap<(usize, (usize, usize)), bool>>;

/// The recursive step of [`in_every_configuration`]: every chain in
/// `choices` lying inside `within` (all of them when `None`) compiles an arm
/// in every configuration, and each live arm holds a guard covered by the
/// chains nested inside that arm. Each level only looks strictly inside an
/// arm, so it ends; `memo` keeps a (guard, arm) answer from being rederived
/// by every outer arm that reaches it.
#[allow(clippy::too_many_arguments)]
fn covered_within(
    choices: &[PreprocChoice],
    within: Option<(usize, usize)>,
    bound: &Node,
    calls: &[Node],
    source: &str,
    is_guard: &dyn Fn(&Node) -> bool,
    precedes: &dyn Fn(&Node, &Node) -> bool,
    memo: &ArmMemo,
) -> bool {
    let guard_covers = |c: &Node, arm: (usize, usize)| {
        let key = (c.start_byte(), arm);
        if let Some(&v) = memo.borrow().get(&key) {
            return v;
        }
        let v = is_guard(c)
            && precedes(c, bound)
            && covered_within(
                &preproc_choices_outside(c, bound, source),
                Some(arm),
                bound,
                calls,
                source,
                is_guard,
                precedes,
                memo,
            );
        memo.borrow_mut().insert(key, v);
        v
    };
    choices
        .iter()
        .filter(|c| within.is_none_or(|(ws, we)| c.arms.iter().all(|&(s, e)| ws <= s && e <= we)))
        .all(|choice| {
            choice.complete
                && choice.arms.iter().zip(&choice.dead).all(|(&arm, &dead)| {
                    dead || calls
                        .iter()
                        .any(|c| (arm.0..arm.1).contains(&c.start_byte()) && guard_covers(c, arm))
                })
        })
}

/// Whether `step` dominates `target` in the function's CFG: every path from
/// entry to `target`'s block passes `step`'s block, or both sit in one block
/// with `step` first. A node outside every block answers `false`.
fn cfg_dominates(cfg: &FunctionCfg, step: &Node, target: &Node) -> bool {
    let (Some(from), Some(to)) = (
        block_of(cfg, step.start_byte()),
        block_of(cfg, target.start_byte()),
    ) else {
        return false;
    };
    if from == to {
        return step.start_byte() < target.start_byte();
    }
    let mut seen: HashSet<usize> = HashSet::from([from]);
    let mut queue: VecDeque<usize> = VecDeque::from([cfg.entry]);
    while let Some(b) = queue.pop_front() {
        if b == to {
            return false;
        }
        if !seen.insert(b) {
            continue;
        }
        queue.extend(cfg.successors(b).into_iter().map(|(n, _)| n));
    }
    true
}

/// The innermost CFG block holding byte `pos`, if any.
fn block_of(cfg: &FunctionCfg, pos: usize) -> Option<usize> {
    cfg.blocks
        .iter()
        .flat_map(|b| {
            b.statements
                .iter()
                .copied()
                .chain(b.condition_range)
                .filter(move |&(s, e)| s <= pos && pos < e)
                .map(move |(s, e)| (e - s, b.id))
        })
        .min()
        .map(|(_, id)| id)
}

/// Whether some CFG path leads from `from` on to `to`. A node outside every
/// block answers `true`: an unplaced store is kept, never dropped.
fn cfg_reaches(cfg: &FunctionCfg, from: &Node, to: &Node) -> bool {
    let (Some(a), Some(b)) = (
        block_of(cfg, from.start_byte()),
        block_of(cfg, to.start_byte()),
    ) else {
        return true;
    };
    if a == b && from.start_byte() < to.start_byte() {
        return true;
    }
    let mut seen: HashSet<usize> = HashSet::new();
    let mut queue: VecDeque<usize> = cfg.successors(a).into_iter().map(|(n, _)| n).collect();
    while let Some(n) = queue.pop_front() {
        if n == b {
            return true;
        }
        if seen.insert(n) {
            queue.extend(cfg.successors(n).into_iter().map(|(m, _)| m));
        }
    }
    false
}

/// The variables that may hold `origin`'s block when `site` runs: the first
/// holder, plus every copy made from a holder since (on any path), minus
/// every holder overwritten since on every path to `site`, replayed in
/// source order. An overwrite in the other arm of an `if` does not end the
/// block's life on this arm. `precedes` decides "on every path", so a
/// function with a `goto` gets the CFG's answer rather than keeping every
/// overwritten copy alive.
fn holders_at(
    origin: &Origin,
    copies: &[Copy],
    site: &Node,
    precedes: &dyn Fn(&Node, &Node) -> bool,
) -> HashSet<usize> {
    let mut held: HashSet<usize> = HashSet::from([origin.holder]);
    for copy in copies
        .iter()
        .filter(|c| c.at > origin.at && c.at < site.start_byte())
    {
        match copy.source {
            Some(s) if held.contains(&s) => {
                held.insert(copy.target);
            }
            _ if precedes(&copy.node, site) => {
                held.remove(&copy.target);
            }
            _ => {}
        }
    }
    held
}

/// Every assignment to a plain variable in `body`, in source order: a copy
/// when the value names another object (`q = p`, `q = p + n`, `q = &p[i]`),
/// an overwrite otherwise.
fn copies_in<'a>(body: &Node<'a>, source: &str) -> Vec<Copy<'a>> {
    let mut out: Vec<Copy> = assignments(body, source)
        .into_iter()
        .filter_map(|(node, target, value)| {
            Some(Copy {
                node,
                at: node.start_byte(),
                target: object_key(&target, source)?,
                source: object_of(&value, source),
            })
        })
        .collect();
    out.sort_by_key(|c| c.at);
    out
}

/// `(assignment, target identifier, value)` for every plain `x = value` and
/// `T *x = value` in `body`.
fn assignments<'a>(body: &Node<'a>, source: &str) -> Vec<(Node<'a>, Node<'a>, Node<'a>)> {
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
            if left.kind() == "identifier" {
                out.push((a, left, right));
            }
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
            out.push((d, ident, value));
        }
    }
    out
}

/// The object an argument or value points into: the variable itself, or the
/// base of `&p[i]`, `p + n`, `p - n`, casts and parentheses peeled.
fn object_of(expr: &Node, source: &str) -> Option<usize> {
    object_key(&pointer_base(expr)?, source)
}

fn pointer_base<'a>(expr: &Node<'a>) -> Option<Node<'a>> {
    let mut n = strip_arg_casts(expr);
    loop {
        match n.kind() {
            "identifier" => return Some(n),
            "parenthesized_expression" => n = strip_arg_casts(&n.named_child(0)?),
            "pointer_expression" => {
                // `&p[i]`: the address of an element is a pointer into `p`.
                let op = n.child(0)?;
                let arg = n.child_by_field_name("argument")?;
                if op.kind() != "&" || arg.kind() != "subscript_expression" {
                    return None;
                }
                n = strip_arg_casts(&arg.child_by_field_name("argument")?);
            }
            "binary_expression" => {
                let op = n.child_by_field_name("operator")?;
                if !matches!(op.kind(), "+" | "-") {
                    return None;
                }
                n = strip_arg_casts(&n.child_by_field_name("left")?);
            }
            // `*p++ = c` writes through `p`.
            "update_expression" => n = strip_arg_casts(&n.child_by_field_name("argument")?),
            _ => return None,
        }
    }
}

/// The variable whose address `expr` takes: `line` in `&line`.
fn address_of<'a>(expr: &Node<'a>) -> Option<Node<'a>> {
    let n = strip_arg_casts(expr);
    if n.kind() != "pointer_expression" || n.child(0)?.kind() != "&" {
        return None;
    }
    let arg = strip_arg_casts(&n.child_by_field_name("argument")?);
    (arg.kind() == "identifier").then_some(arg)
}

/// The pointer a store writes through: `p` in `p[i] = ...`, `*p = ...` and
/// `*(p + i) = ...`.
fn written_through<'a>(left: &Node<'a>) -> Option<Node<'a>> {
    match left.kind() {
        "subscript_expression" => left.child_by_field_name("argument"),
        "pointer_expression" if left.child(0).is_some_and(|op| op.kind() == "*") => {
            left.child_by_field_name("argument")
        }
        _ => None,
    }
}

/// An identifier's declaration, as the declarator's start byte (ADR-0006).
fn object_key(ident: &Node, source: &str) -> Option<usize> {
    if ident.kind() != "identifier" {
        return None;
    }
    let name = get_node_text(ident, source);
    let (_, declarator) = resolve_identifier_declarator(ident, name, source)?;
    Some(declarator.start_byte())
}

/// The spelling of the sink argument that names `object`.
fn object_name(call: &Node, object: usize, source: &str) -> String {
    call_args(call)
        .iter()
        .filter_map(pointer_base)
        .find(|b| object_key(b, source) == Some(object))
        .map(|b| get_node_text(&b, source).to_string())
        .unwrap_or_default()
}

/// Whether a `memset`/`memset_s` call fills its destination with data: a
/// fill argument that is not a literal zero. A zeroing fill is a clear.
fn is_data_fill(args: &[Node], source: &str, callee: &str) -> bool {
    let fill = match callee {
        "memset" => args.get(1),
        "memset_s" => args.get(2),
        _ => return false,
    };
    fill.is_some_and(|f| !is_zero_literal(f, source))
}

fn is_zero_literal(n: &Node, source: &str) -> bool {
    matches!(
        get_node_text(n, source).trim(),
        "0" | "'\\0'" | "0x0" | "0x00"
    )
}

/// Whether an array initializer writes data: anything but zeros (`{0}`,
/// `{ 0, 0 }`, `""`).
fn writes_data(init: &Node, source: &str) -> bool {
    match init.kind() {
        "initializer_list" => (0..init.named_child_count())
            .filter_map(|i| init.named_child(i))
            .filter(|c| c.kind() != "comment")
            .any(|c| !is_zero_literal(&c, source)),
        "string_literal" | "concatenated_string" => get_node_text(init, source).trim() != "\"\"",
        _ => true,
    }
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

fn function_name(func: &Node, source: &str) -> Option<String> {
    let declarator = func.child_by_field_name("declarator")?;
    let name = get_identifier_from_declarator(&declarator, source);
    (!name.is_empty()).then(|| name.to_string())
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
