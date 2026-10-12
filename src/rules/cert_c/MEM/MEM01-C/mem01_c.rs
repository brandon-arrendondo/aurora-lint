// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! MEM01-C: Store a new value in pointers immediately after free()
//!
//! "Immediately" means before the pointer variable can next be read or escape
//! (maintainer ruling). Forward reachability over the
//! CFG from each free() looks for the first thing that happens to the freed
//! lvalue on every path:
//! - it is stored to (reset): the path is fine;
//! - it is read, passed on or freed again: the pointer was left dangling
//!   across a read (the finding MEM30-C also makes at the later use);
//! - the path ends while the lvalue outlives the function (a global, a
//!   function-local `static`, a member reached through a pointer): the pointer
//!   escapes still holding the freed address.
//!
//! The lvalue is an identifier or a member path (`s->buf`, `g.p`). A freed
//! local, parameter or member of a local struct dies at function exit, so it
//! escapes nothing. The destructor idiom is exempt: `free(s->buf); free(s);`
//! frees the object the member lives in next, so the member dies with it. A
//! path that ends the process (`exit()`) escapes nothing either. The calls
//! that free are `free`, C23 `free_sized` / `free_aligned_sized` and a
//! project-declared deallocator.

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::{self as cfg_mod, FunctionCfg};
use crate::analyze::context::ProjectContext;
use crate::analyze::context::ScopedTable;
use crate::analyze::dataflow::find_node_at_range;
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::points_to::{lvalue_of, LValue};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::call_roles;
use crate::utility::cert_c::clearing_extent::cleared_extent;
use crate::utility::cert_c::node_children::NodeChildren;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tree_sitter::Node;

pub struct Mem01C {
    function_cfgs: RefCell<HashMap<usize, FunctionCfg>>,
    /// Cross-file function summaries from prescan (an earlier fix follow-on to 320/321).
    cross_file_summaries: RefCell<ScopedTable<FunctionSummary>>,
    /// [`Mem01C::build_read_only_params`] of `cross_file_summaries`, built
    /// when they are set rather than once per function: it depends on
    /// nothing else.
    read_only_params: RefCell<Arc<HashMap<String, HashSet<usize>>>>,
    /// [`Mem01C::build_freeing_wrappers`] of `cross_file_summaries`, built
    /// with `read_only_params` for the same reason.
    freeing_wrappers: RefCell<Arc<HashMap<String, HashSet<usize>>>>,
    /// The functions the project defines (those with a summary), built with
    /// `read_only_params` for the same reason.
    defined_functions: RefCell<Arc<HashSet<String>>>,
}

/// Per-callee parameter indices confirmed to be read-only-dereferenced,
/// derived from `FunctionSummary`. Threaded through the classification
/// helpers so an `&ptr_name` output-param argument can be resolved precisely
/// instead of always assumed safe. Confirmed writers and unknown
/// callees both fall back to the existing "assume safe reassignment"
/// behavior (see `call_address_of_action`), so only the read-only set needs
/// tracking.
struct AddressOfCallContext {
    read_only_params: Arc<HashMap<String, HashSet<usize>>>,
    /// Per-callee parameter indices the callee's summary proves it frees: a
    /// wrapper with a body (`os_free(p)`) that no `[environment.deallocators]`
    /// entry names. The destructor idiom ends with one of these as often as
    /// with `free`.
    freeing_wrappers: Arc<HashMap<String, HashSet<usize>>>,
    /// The functions the project defines (those with a summary): a call to
    /// one can read a global or `static` that still holds a freed address,
    /// where a library function cannot.
    defined_functions: Arc<HashSet<String>>,
}

impl Mem01C {
    pub fn new() -> Self {
        Self {
            function_cfgs: RefCell::new(HashMap::new()),
            cross_file_summaries: RefCell::default(),
            read_only_params: RefCell::default(),
            freeing_wrappers: RefCell::default(),
            defined_functions: RefCell::default(),
        }
    }

    /// Functions confirmed to dereference a pointer parameter WITHOUT ever
    /// writing through it. Passing `&ptr_name` to one of these is a genuine
    /// read of the (possibly freed) pointer value, not a safe reassignment.
    ///
    /// The same three-state test as EXP33-C's `build_read_only_deref_fns`,
    /// and deliberately the same code shape so the two cannot drift again.
    /// `dereferences_params - modifies_params` alone was this rule's test
    /// until an earlier fix, which is what EXP33-C's was before its
    /// MUST-write and three-state fixes; MEM01-C inherited EXP33-C's
    /// population-side fix for free
    /// (`dereferences_params` is a shared `FunctionSummary` field) and none
    /// of the consumption-side ones.
    ///
    /// Piece (a), an earlier fix: `credit_modifies_params` withholds a
    /// parameter from the MAY set while its forwarding obligation is still
    /// unresolved (`modifies_params_pending`), so a merely-pending parameter
    /// is indistinguishable here from one proven never written. Excluding it
    /// stops "not proven to write" doubling as "proven not to write".
    ///
    /// Piece (b), an earlier fix: `forwards_to_indirect_call` is the
    /// Unknown-due-to-indirection state. A callee that hands the parameter to
    /// a call through a function pointer or a driver-ops struct field
    /// (`hapd->driver->read_sta_data(...)`) can never be proven to write it
    /// OR not to, so the honest answer is neither, and this map must suppress
    /// rather than assert (ADR-0001). Resolving the indirect target is
    /// points-to analysis the design doc explicitly declines (piece (c) of
    /// docs/design/exp33-c-cross-file-uninit-architecture.md).
    ///
    /// What that costs HERE, stated because the consumer differs: MEM01-C
    /// reads this map to say a call is a genuine read of a possibly-freed
    /// pointer. A parameter dropped by either filter stops earning that claim,
    /// so the effect is withheld MEM01-C reports, never new ones.
    /// Callees whose summary frees a parameter, by name.
    fn build_freeing_wrappers(&self) -> HashMap<String, HashSet<usize>> {
        self.cross_file_summaries
            .borrow()
            .iter()
            .filter(|(_, summary)| !summary.frees_params.is_empty())
            .map(|(name, summary)| (name.clone(), summary.frees_params.clone()))
            .collect()
    }

    fn build_read_only_params(&self) -> HashMap<String, HashSet<usize>> {
        let summaries = self.cross_file_summaries.borrow();
        let mut result = HashMap::new();
        for (name, summary) in summaries.iter() {
            let read_only: HashSet<usize> = summary
                .dereferences_params
                .iter()
                .filter(|idx| !summary.modifies_params.contains(idx))
                .filter(|idx| !summary.modifies_params_pending.contains_key(idx))
                .filter(|idx| !summary.forwards_to_indirect_call.contains(idx))
                .copied()
                .collect();
            if !read_only.is_empty() {
                result.insert(name.clone(), read_only);
            }
        }
        result
    }
}

/// How a freed pointer was left behind.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Hazard {
    /// Read, passed on or freed again before any store.
    Read,
    /// A path ends while the lvalue outlives the function.
    Escapes,
}

#[derive(Debug, PartialEq)]
enum PtrAction {
    /// ptr = ... (any assignment to ptr, including NULL)
    Reassigned,
    /// free(ptr) called again
    FreedAgain,
    /// ptr used: dereferenced, indexed, passed to function, returned, etc.
    Used,
    /// Statement does not involve ptr
    Irrelevant,
}

impl CertRule for Mem01C {
    fn reads_header_facts(&self) -> bool {
        true
    }

    fn rule_id(&self) -> &'static str {
        "MEM01-C"
    }

    fn description(&self) -> &'static str {
        "Store a new value in pointers immediately after free()"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "MEM01-C"
    }

    fn set_function_cfgs(&self, cfgs: &HashMap<usize, FunctionCfg>) {
        *self.function_cfgs.borrow_mut() = cfgs.clone();
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.cross_file_summaries.borrow_mut() = context.function_summaries.clone();
        *self.read_only_params.borrow_mut() = Arc::new(self.build_read_only_params());
        *self.freeing_wrappers.borrow_mut() = Arc::new(self.build_freeing_wrappers());
        *self.defined_functions.borrow_mut() = Arc::new(
            self.cross_file_summaries
                .borrow()
                .iter()
                .map(|(name, _)| name.clone())
                .collect(),
        );
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Mem01C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() == "function_definition" {
            self.check_function(node, source, violations);
            return; // don't recurse into function — already handled
        }
        for child in node.child_nodes() {
            self.check_node(&child, source, violations);
        }
    }

    fn check_function(&self, func_node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let body = match func_node.child_by_field_name("body") {
            Some(b) => b,
            None => return,
        };

        let addr_ctx = AddressOfCallContext {
            read_only_params: Arc::clone(&self.read_only_params.borrow()),
            freeing_wrappers: Arc::clone(&self.freeing_wrappers.borrow()),
            defined_functions: Arc::clone(&self.defined_functions.borrow()),
        };

        // Get pre-built CFG or build one on the fly
        let cfgs = self.function_cfgs.borrow();
        let inline_cfg;
        let cfg = if let Some(c) = cfgs.get(&func_node.start_byte()) {
            c
        } else if let Some(c) = cfg_mod::build_function_cfg(func_node, source) {
            inline_cfg = c;
            &inline_cfg
        } else {
            return; // no CFG available
        };

        // Find all free() calls in this function
        let free_calls = self.collect_free_calls(&body, source);

        for site in free_calls {
            let hazard = self.ptr_hazard_after_free(cfg, &body, source, &site, &addr_ctx);
            if let Some(hazard) = hazard {
                let name = &site.key;
                let message = match hazard {
                    Hazard::Read => format!(
                        "Pointer '{}' is read, passed on or freed again after free() without \
                         being set again",
                        name
                    ),
                    Hazard::Escapes => format!(
                        "Pointer '{}' outlives this function still holding the freed address: \
                         it is not set to NULL after free()",
                        name
                    ),
                };
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message,
                    file_path: String::new(),
                    line: site.line,
                    column: site.column,
                    suggestion: Some(format!(
                        "Set '{} = NULL;' after free({}) or remove the subsequent use",
                        name, name
                    )),
                    ..Default::default()
                });
            }
        }
    }

    /// Every free() of an lvalue the function could reset.
    fn collect_free_calls(&self, node: &Node, source: &str) -> Vec<FreeSite> {
        let mut results = Vec::new();
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            let Some(arg) = freed_argument(&call, source) else {
                continue;
            };
            let Some(site) = FreeSite::of(&call, &arg, source) else {
                continue;
            };
            results.push(site);
        }
        results
    }

    /// Forward through the CFG from the free() call site: how the freed
    /// lvalue is left on the first path that does not store to it, if any.
    fn ptr_hazard_after_free(
        &self,
        cfg: &FunctionCfg,
        body: &Node,
        source: &str,
        site: &FreeSite,
        addr_ctx: &AddressOfCallContext,
    ) -> Option<Hazard> {
        let containing_block = match find_block_containing(cfg, site.free_byte) {
            Some(b) => b,
            None => return Some(Hazard::Read), // conservative: can't locate block, flag it
        };

        // Scan remaining statements in the containing block after the free
        match self.scan_block_from(containing_block, body, source, site, addr_ctx) {
            Some(PtrAction::FreedAgain) | Some(PtrAction::Used) => return Some(Hazard::Read),
            Some(PtrAction::Reassigned) => return None,
            _ => {} // fall through to BFS
        }
        if site.persists && path_ends_at(cfg, containing_block.id) {
            return Some(Hazard::Escapes);
        }

        // BFS through successor blocks
        let mut visited: HashSet<usize> = HashSet::new();
        visited.insert(containing_block.id);
        let mut queue: VecDeque<usize> = VecDeque::new();

        for (succ_id, _edge) in cfg.successors(containing_block.id) {
            queue.push_back(succ_id);
        }

        while let Some(block_id) = queue.pop_front() {
            if !visited.insert(block_id) {
                continue; // already visited
            }

            let block = match cfg.get_block(block_id) {
                Some(b) => b,
                None => continue,
            };

            // Scan all statements in this block from the start
            match self.scan_block_all(block, body, source, site, addr_ctx) {
                Some(PtrAction::FreedAgain) | Some(PtrAction::Used) => return Some(Hazard::Read),
                Some(PtrAction::Reassigned) => continue, // safe on this path
                _ => {
                    if site.persists && path_ends_at(cfg, block_id) {
                        return Some(Hazard::Escapes);
                    }
                    // No decisive action, continue to successors
                    for (succ_id, _edge) in cfg.successors(block_id) {
                        queue.push_back(succ_id);
                    }
                }
            }
        }

        None // all reachable paths are safe
    }

    /// Scan statements in a block starting AFTER after_byte.
    /// Returns the first decisive PtrAction found, or None.
    fn scan_block_from(
        &self,
        block: &crate::analyze::cfg::BasicBlock,
        body: &Node,
        source: &str,
        site: &FreeSite,
        addr_ctx: &AddressOfCallContext,
    ) -> Option<PtrAction> {
        for &(start, end) in &block.statements {
            if start <= site.free_byte {
                continue;
            }
            if let Some(stmt_node) = find_node_at_range(body, start, end) {
                let action = classify_stmt_on_path(&stmt_node, source, site, addr_ctx);
                if action != PtrAction::Irrelevant {
                    return Some(action);
                }
            }
        }
        None
    }

    /// Scan all statements in a block from the beginning.
    fn scan_block_all(
        &self,
        block: &crate::analyze::cfg::BasicBlock,
        body: &Node,
        source: &str,
        site: &FreeSite,
        addr_ctx: &AddressOfCallContext,
    ) -> Option<PtrAction> {
        for &(start, end) in &block.statements {
            if let Some(stmt_node) = find_node_at_range(body, start, end) {
                let action = classify_stmt_on_path(&stmt_node, source, site, addr_ctx);
                if action != PtrAction::Irrelevant {
                    return Some(action);
                }
            }
        }
        None
    }
}

/// One free() of an lvalue, and what the lvalue is.
struct FreeSite {
    /// The freed lvalue with its whitespace removed: `p`, `s->buf`, `g.p`.
    key: String,
    free_byte: usize,
    line: usize,
    column: usize,
    /// The lvalue outlives the function: a global, a `static`, or a member
    /// reached through a pointer. A path that ends with it unset escapes.
    persists: bool,
    /// The lvalue is a global or `static` object itself (or a `.` member of
    /// one), not reached through a pointer: any function the project defines
    /// can read it.
    global: bool,
    /// The objects a member path lives in, innermost first (`s->buf` lives in
    /// `s`). Freeing one of them ends the member too (the destructor idiom).
    containers: Vec<String>,
    /// The lvalue as the points-to layer reads it, for asking whether a
    /// clearing call's write reaches it.
    lvalue: Option<LValue>,
}

impl FreeSite {
    /// `None` when the argument is not an lvalue a store could reset (a call
    /// result, a string literal).
    fn of(call: &Node, arg: &Node, source: &str) -> Option<Self> {
        let arg = strip_parens_and_casts(arg);
        // `ws[i].buf` names a different object whenever `i` changes, and the
        // key is text: leave an indexed path to the rules that track values.
        if query::find_first_descendant(arg, |n| n.kind() == "subscript_expression").is_some() {
            return None;
        }
        let key = compact(get_node_text(&arg, source));
        let pos = call.start_position();
        let (persists, mut containers) = match arg.kind() {
            "identifier" => (identifier_outlives_function(&arg, source), Vec::new()),
            "field_expression" => (
                member_outlives_function(&arg, source),
                member_containers(&arg, source),
            ),
            _ => return None,
        };
        // `T *t = (T *)v;` names one object twice: freeing `v` after `t->m`
        // frees the object `t->m` lives in.
        if let Some(root) = containers.last().cloned() {
            containers.extend(initializer_aliases(&arg, &root, source));
        }
        let global = persists && !key.contains("->");
        Some(Self {
            key,
            global,
            free_byte: call.start_byte(),
            line: pos.row + 1,
            column: pos.column + 1,
            persists,
            containers,
            lvalue: lvalue_of(&arg, source),
        })
    }
}

/// The other names for the object variable `root` names, through
/// declarations whose initializer is one other variable (a cast around it
/// aside): `vtab *t = (vtab *)v;` makes `t` and `v` the same pointer. One
/// level at a time, in both directions, within the function holding `site`.
fn initializer_aliases(site: &Node, root: &str, source: &str) -> Vec<String> {
    let mut function = *site;
    while function.kind() != "function_definition" {
        match function.parent() {
            Some(p) => function = p,
            None => return Vec::new(),
        }
    }
    let mut pairs: Vec<(String, String)> = Vec::new();
    for init in query::find_descendants_of_kind(function, "init_declarator") {
        let (Some(declarator), Some(value)) = (
            init.child_by_field_name("declarator"),
            init.child_by_field_name("value"),
        ) else {
            continue;
        };
        let value = strip_parens_and_casts(&value);
        if value.kind() != "identifier" {
            continue;
        }
        let name = ast_utils::get_identifier_from_declarator(&declarator, source);
        if !name.is_empty() {
            pairs.push((name, get_node_text(&value, source).to_string()));
        }
    }
    let mut class = vec![root.to_string()];
    let mut grew = true;
    while grew {
        grew = false;
        for (a, b) in &pairs {
            for (x, y) in [(a, b), (b, a)] {
                if class.contains(x) && !class.contains(y) {
                    class.push(y.clone());
                    grew = true;
                }
            }
        }
    }
    class.retain(|name| name != root);
    class
}

fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

fn strip_parens_and_casts<'a>(node: &Node<'a>) -> Node<'a> {
    let mut current = *node;
    loop {
        let inner = match current.kind() {
            "parenthesized_expression" => current.named_child(0),
            "cast_expression" => current.child_by_field_name("value"),
            _ => None,
        };
        match inner {
            Some(n) => current = n,
            None => return current,
        }
    }
}

/// The argument a call frees: `free`'s, a declared deallocator's, or the
/// first argument of C23 `free_sized` / `free_aligned_sized`
/// (`call_roles::frees_argument` names neither, and it is shared with rules
/// whose summaries are cached).
fn freed_argument<'t>(call: &Node<'t>, source: &str) -> Option<Node<'t>> {
    if let Some(arg) = call_roles::freed_argument(call, source) {
        return Some(arg);
    }
    let callee = call.child_by_field_name("function")?;
    if !matches!(
        get_node_text(&callee, source),
        "free_sized" | "free_aligned_sized"
    ) {
        return None;
    }
    call.child_by_field_name("arguments")?
        .named_children(&mut call.walk())
        .find(|a| a.kind() != "comment")
}

/// Whether `call` is a memory-clearing call (`memset`, `bzero`, ...) whose
/// write reaches `lvalue`.
fn clearing_call_covers(call: &Node, lvalue: &LValue, source: &str) -> bool {
    let Some(callee) = call.child_by_field_name("function") else {
        return false;
    };
    if !call_roles::is_memory_clearing_call(get_node_text(&callee, source)) {
        return false;
    }
    let args = crate::analyze::macro_semantics::positional_args(call);
    let Some((dest, rest)) = args.split_first() else {
        return false;
    };
    cleared_extent(dest, rest, source).is_some_and(|extent| extent.covers(lvalue))
}

/// The arguments a call passes in the positions its callee's summary frees.
fn wrapper_freed_arguments<'t>(
    call: &Node<'t>,
    source: &str,
    addr_ctx: &AddressOfCallContext,
) -> Option<Vec<Node<'t>>> {
    let callee = call.child_by_field_name("function")?;
    let positions = addr_ctx
        .freeing_wrappers
        .get(get_node_text(&callee, source))?;
    let arguments = call.child_by_field_name("arguments")?;
    let args: Vec<Node<'t>> = arguments
        .named_children(&mut arguments.walk())
        .filter(|a| a.kind() != "comment")
        .collect();
    Some(
        positions
            .iter()
            .filter_map(|&i| args.get(i).copied())
            .collect(),
    )
}

/// Whether a path through `block_id` leaves the function.
///
/// `cfg.exits` is not used: with no explicit `return` it names the last block
/// created, which for nested conditionals is a join block mid-function.
fn path_ends_at(cfg: &FunctionCfg, block_id: usize) -> bool {
    cfg.successors(block_id).is_empty()
}

/// A global, or a block-scope `static`/`extern` declaration.
fn identifier_outlives_function(ident: &Node, source: &str) -> bool {
    let name = get_node_text(ident, source);
    let Some((decl, _)) = ast_utils::resolve_identifier_declarator(ident, name, source) else {
        return false;
    };
    if decl.kind() != "declaration" {
        return false; // a parameter is the callee's own copy
    }
    let mut inside_function = false;
    let mut current = decl.parent();
    while let Some(n) = current {
        if n.kind() == "function_definition" {
            inside_function = true;
            break;
        }
        current = n.parent();
    }
    !inside_function
        || ["static", "extern", "_Thread_local", "thread_local"]
            .iter()
            .any(|class| ast_utils::declaration_has_storage_class(&decl, class, source))
}

/// A member path outlives the function unless it is a `.`-only path into a
/// local (or by-value parameter) struct.
fn member_outlives_function(expr: &Node, source: &str) -> bool {
    let mut current = *expr;
    loop {
        match current.kind() {
            "field_expression" => {
                if current
                    .child_by_field_name("operator")
                    .is_some_and(|op| get_node_text(&op, source) == "->")
                {
                    return true;
                }
                match current.child_by_field_name("argument") {
                    Some(inner) => current = inner,
                    None => return false,
                }
            }
            "subscript_expression" => match current.child_by_field_name("argument") {
                Some(inner) => current = inner,
                None => return false,
            },
            "parenthesized_expression" => match current.named_child(0) {
                Some(inner) => current = inner,
                None => return false,
            },
            "identifier" => return identifier_outlives_function(&current, source),
            // `(*p).buf`, `get()->buf`: through a pointer.
            _ => return true,
        }
    }
}

/// `s->buf` lives in `s`; `a.b->c` in `a.b` and `a`.
fn member_containers(expr: &Node, source: &str) -> Vec<String> {
    let mut containers = Vec::new();
    let mut current = *expr;
    while current.kind() == "field_expression" {
        let Some(inner) = current.child_by_field_name("argument") else {
            break;
        };
        let inner = strip_parens_and_casts(&inner);
        containers.push(compact(get_node_text(&inner, source)));
        current = inner;
    }
    containers
}

/// Classify one statement on a path from the free: the path-ending and
/// destructor-idiom cases first, then what the statement does to the key.
fn classify_stmt_on_path(
    node: &Node,
    source: &str,
    site: &FreeSite,
    addr_ctx: &AddressOfCallContext,
) -> PtrAction {
    if node.kind() == "expression_statement" {
        if let Some(call) = node.child(0).filter(|c| c.kind() == "call_expression") {
            // The object the member lives in is freed next: the member dies with it.
            let frees_container = |arg: &Node| {
                let arg = compact(get_node_text(&strip_parens_and_casts(arg), source));
                site.containers.contains(&arg)
            };
            if freed_argument(&call, source).is_some_and(|arg| frees_container(&arg)) {
                return PtrAction::Reassigned;
            }
            if let Some(freed) = wrapper_freed_arguments(&call, source, addr_ctx) {
                if freed.iter().any(frees_container) {
                    return PtrAction::Reassigned;
                }
            }
        }
        // A clearing call that writes over the freed member resets it:
        // `free(c->a); memset(&c->csr, 0, (u8*)&c[1] - (u8*)&c->csr);`.
        if let (Some(call), Some(lvalue)) = (
            node.child(0).filter(|c| c.kind() == "call_expression"),
            site.lvalue.as_ref(),
        ) {
            if clearing_call_covers(&call, lvalue, source) {
                return PtrAction::Reassigned;
            }
        }
        // A path that ends the process escapes nothing.
        if node
            .child(0)
            .filter(|c| c.kind() == "call_expression")
            .and_then(|c| c.child_by_field_name("function"))
            .is_some_and(|f| {
                matches!(
                    get_node_text(&f, source),
                    "exit" | "_exit" | "_Exit" | "quick_exit" | "abort"
                )
            })
        {
            return PtrAction::Reassigned;
        }
    }
    let action = classify_stmt_for_ptr(node, source, &site.key, addr_ctx);
    if action == PtrAction::Irrelevant
        && site.persists
        && call_can_read_dangling(node, source, site, addr_ctx)
    {
        return PtrAction::Used;
    }
    action
}

/// Whether `node` calls a function that can read the freed value without
/// naming it: one handed the object the member lives in (`log_state(s)` after
/// `free(s->buf)`), or, for a global or `static`, any function the project
/// defines. A deallocator is no such call.
fn call_can_read_dangling(
    node: &Node,
    source: &str,
    site: &FreeSite,
    addr_ctx: &AddressOfCallContext,
) -> bool {
    query::find_descendants_of_kind(*node, "call_expression")
        .into_iter()
        .chain((node.kind() == "call_expression").then_some(*node))
        .any(|call| {
            if freed_argument(&call, source).is_some()
                || wrapper_freed_arguments(&call, source, addr_ctx).is_some_and(|f| !f.is_empty())
            {
                return false;
            }
            let hands_container = call.child_by_field_name("arguments").is_some_and(|args| {
                args.named_children(&mut args.walk()).any(|arg| {
                    site.containers.contains(&compact(get_node_text(
                        &strip_parens_and_casts(&arg),
                        source,
                    )))
                })
            });
            let callee = call
                .child_by_field_name("function")
                .map(|f| get_node_text(&f, source).to_string())
                .unwrap_or_default();
            hands_container || (site.global && addr_ctx.defined_functions.contains(&callee))
        })
}

// ---------------------------------------------------------------------------
// Statement classification
// ---------------------------------------------------------------------------

/// Classify what a statement does to ptr_name.
fn classify_stmt_for_ptr(
    node: &Node,
    source: &str,
    ptr_name: &str,
    addr_ctx: &AddressOfCallContext,
) -> PtrAction {
    match node.kind() {
        "expression_statement" => {
            if let Some(expr) = node.child(0) {
                classify_expr_for_ptr(&expr, source, ptr_name, addr_ctx)
            } else {
                PtrAction::Irrelevant
            }
        }
        "return_statement" => {
            // return ptr; is a use, but `return fmt(&ptr, ...)` rebinds it
            if node.child_count() > 1 {
                if let Some(expr) = node.child(1) {
                    return nested_action_for_ptr(&expr, source, ptr_name, addr_ctx);
                }
            }
            PtrAction::Irrelevant
        }
        "declaration" => {
            // Check if ptr_name is the variable being declared (= reassignment)
            // vs used in the initializer of a different variable
            if let Some(declarator) = find_declarator_name(node, source) {
                // A declaration of the variable a member path hangs off
                // (`NodeWriter *n = &w[i];` at the top of a loop body) names a
                // new object each time it runs.
                if declarator == ptr_name || is_member_of(ptr_name, &declarator) {
                    return PtrAction::Reassigned;
                }
            }
            // Check if ptr_name appears in the initializer (e.g., int *q = ptr;),
            // unless it only appears as `&ptr_name` handed to an output-param
            // call (`int n = fmt(&ptr, ...)`).
            nested_action_for_ptr(node, source, ptr_name, addr_ctx)
        }
        // A while/for loop condition is stored as its header block's single
        // statement, wrapped in a parenthesized_expression (see cfg.rs
        // process_while/process_for). `while ((ptr = next()) != NULL)`
        // reassigns ptr *within* the condition before any use — the assignment
        // is nested inside a binary_expression, not a top-level
        // expression_statement, so it's invisible to classify_expr_for_ptr's
        // top-level match. Recognize it directly here.
        "parenthesized_expression" => {
            if subtree_assigns_identifier(node, source, ptr_name) {
                return PtrAction::Reassigned;
            }
            if let Some(action) = subtree_address_of_call_action(node, source, ptr_name, addr_ctx) {
                return action;
            }
            if subtree_contains_identifier(node, source, ptr_name) {
                PtrAction::Used
            } else {
                PtrAction::Irrelevant
            }
        }
        // A `for` update clause is stored as its own expression, not wrapped in
        // an expression_statement: `for (...; p = next)` stores to p before
        // the condition reads it.
        "assignment_expression" | "call_expression" | "update_expression" | "comma_expression" => {
            classify_expr_for_ptr(node, source, ptr_name, addr_ctx)
        }
        _ => {
            // For any other statement kind, check if ptr_name appears. A
            // `&ptr_name` passed to a call nested anywhere in the statement
            // (e.g. inside an if-condition: `if(read_pair(..., &ptr) ==
            // NULL)`) is the output-param idiom, not a use of the old value
            // (see the "call_expression" arm of classify_expr_for_ptr) --
            // unless the callee is known to only dereference,
            // never write, that parameter.
            nested_action_for_ptr(node, source, ptr_name, addr_ctx)
        }
    }
}

/// Classify an expression for ptr_name interaction.
fn classify_expr_for_ptr(
    expr: &Node,
    source: &str,
    ptr_name: &str,
    addr_ctx: &AddressOfCallContext,
) -> PtrAction {
    match expr.kind() {
        "assignment_expression" => {
            if let Some(left) = expr.child_by_field_name("left") {
                let left_text = compact(get_node_text(&left, source));
                if left_text == ptr_name || is_member_of(ptr_name, &left_text) {
                    return PtrAction::Reassigned;
                }
                // `ptr[0] = ...` reads the freed pointer whatever the RHS does
                if subtree_contains_identifier(&left, source, ptr_name) {
                    return PtrAction::Used;
                }
            }
            // Check if ptr is used on the RHS (e.g., x = *ptr). A stored
            // output-param call (`len = fmt(&ptr, ...)`) rebinds it instead.
            nested_action_for_ptr(expr, source, ptr_name, addr_ctx)
        }
        "call_expression" => {
            if let Some(func) = expr.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);
                if func_name == "free" {
                    if let Some(args) = expr.child_by_field_name("arguments") {
                        if arg_list_contains_identifier(&args, source, ptr_name) {
                            return PtrAction::FreedAgain;
                        }
                    }
                } else if freed_argument(expr, source).is_some_and(|arg| {
                    compact(get_node_text(&strip_parens_and_casts(&arg), source)) == ptr_name
                }) {
                    return PtrAction::FreedAgain;
                }
            }
            // `&ptr_name` passed to a call is the output-param idiom (e.g.
            // `read_string_pair(props, id, &name, &value, false)` writing a
            // fresh pointer through the argument) -- treat it like a
            // reassignment rather than a use, UNLESS the callee is known
            // (via cross-file `FunctionSummary`) to only
            // dereference that parameter and never write through it, in
            // which case it's a genuine read of the (possibly freed)
            // pointer value. Without this, CFG paths that reach a
            // *different*, mutually-exclusive branch reusing the same
            // variable name (e.g. sibling switch-case arms revisited via a
            // loop back-edge) misclassify the output-param call as a plain
            // "use" of the still-freed pointer.
            if let Some(action) = call_address_of_action(expr, source, ptr_name, addr_ctx) {
                return action;
            }
            if let Some(args) = expr.child_by_field_name("arguments") {
                if arg_list_contains_identifier(&args, source, ptr_name) {
                    return PtrAction::Used;
                }
            }
            PtrAction::Irrelevant
        }
        "comma_expression" => {
            // `p = next, n++`: evaluated left to right
            for part in [
                expr.child_by_field_name("left"),
                expr.child_by_field_name("right"),
            ]
            .into_iter()
            .flatten()
            {
                let action = classify_expr_for_ptr(&part, source, ptr_name, addr_ctx);
                if action != PtrAction::Irrelevant {
                    return action;
                }
            }
            PtrAction::Irrelevant
        }
        "update_expression" => {
            // ptr++ or ptr--
            if subtree_contains_identifier(expr, source, ptr_name) {
                return PtrAction::Used;
            }
            PtrAction::Irrelevant
        }
        // `(void)fmt(&ptr, ...)`, `fmt(&ptr, ...) < 0` and the like
        _ => nested_action_for_ptr(expr, source, ptr_name, addr_ctx),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if an identifier matching ptr_name appears in the subtree.
/// Matches only identifier nodes (not substrings of other identifiers).
fn subtree_contains_identifier(node: &Node, source: &str, name: &str) -> bool {
    if is_member_path(name) {
        return query::find_first_descendant(*node, |n| {
            matches!(n.kind(), "field_expression" | "subscript_expression")
                && compact(get_node_text(&n, source)) == name
        })
        .is_some();
    }
    query::find_first_descendant(*node, |n| {
        n.kind() == "identifier" && get_node_text(&n, source) == name
    })
    .is_some()
}

/// A key naming a member (`s->buf`, `g.p`, `a[0]`), not a plain variable.
fn is_member_path(key: &str) -> bool {
    key.contains("->") || key.contains('.') || key.contains('[')
}

/// Whether storing to `left` replaces the object `key` lives in: `s = other`
/// ends `s->buf`.
fn is_member_of(key: &str, left: &str) -> bool {
    key.strip_prefix(left).is_some_and(|rest| {
        rest.starts_with("->") || rest.starts_with('.') || rest.starts_with('[')
    })
}

/// True if an `assignment_expression` with `ptr_name` as its LHS appears
/// anywhere in the subtree (e.g. nested inside a condition's
/// parenthesized/binary wrapper: `(ptr = next()) != NULL`). See the
/// `parenthesized_expression` case of `classify_stmt_for_ptr`.
fn subtree_assigns_identifier(node: &Node, source: &str, name: &str) -> bool {
    query::find_first_descendant(*node, |n| {
        if n.kind() != "assignment_expression" {
            return false;
        }
        n.child_by_field_name("left")
            .map(|left| {
                let left = compact(get_node_text(&left, source));
                left == name || is_member_of(name, &left)
            })
            .unwrap_or(false)
    })
    .is_some()
}

/// Find a call expression anywhere in the subtree that passes `&ptr_name` as
/// a top-level argument (the output-param idiom: `read_pair(..., &ptr_name)`)
/// and classify it via `call_address_of_action`. Catches cases where such a
/// call is nested inside a comparison, e.g. an if/while condition
/// (`if(read_pair(..., &ptr) == NULL)`).
fn subtree_address_of_call_action(
    node: &Node,
    source: &str,
    name: &str,
    addr_ctx: &AddressOfCallContext,
) -> Option<PtrAction> {
    for call in query::find_descendants_of_kind(*node, "call_expression") {
        if let Some(action) = call_address_of_action(&call, source, name, addr_ctx) {
            return Some(action);
        }
    }
    None
}

/// Classify a subtree that is not itself a reassignment of `name`: an
/// output-param call nested anywhere in it (`len = fmt(&name, ...)`) decides
/// via `call_address_of_action`; otherwise any mention of `name` is a use.
fn nested_action_for_ptr(
    node: &Node,
    source: &str,
    name: &str,
    addr_ctx: &AddressOfCallContext,
) -> PtrAction {
    if let Some(action) = subtree_address_of_call_action(node, source, name, addr_ctx) {
        action
    } else if subtree_contains_identifier(node, source, name) {
        PtrAction::Used
    } else {
        PtrAction::Irrelevant
    }
}

/// Given a `call_expression`, if it passes `&name` as a top-level argument,
/// classify the call: `Reassigned` if the callee is a known writer of that
/// parameter, `Used` if the callee is known to only dereference it (a
/// genuine read of the possibly-freed value), or `Reassigned` as the
/// conservative fallback when the callee's behavior is unknown (
/// keeps the mosquitto output-param fix as a floor when no summary exists).
/// Returns `None` if the call does not take `&name` as an argument at all.
fn call_address_of_action(
    call: &Node,
    source: &str,
    name: &str,
    addr_ctx: &AddressOfCallContext,
) -> Option<PtrAction> {
    let args = call.child_by_field_name("arguments")?;
    let idx = address_of_arg_index(&args, source, name)?;
    let func_name = call
        .child_by_field_name("function")
        .map(|f| get_node_text(&f, source).to_string())
        .unwrap_or_default();
    if addr_ctx
        .read_only_params
        .get(&func_name)
        .is_some_and(|indices| indices.contains(&idx))
    {
        Some(PtrAction::Used)
    } else {
        // Confirmed writer, or unknown callee -- assume safe reassignment.
        Some(PtrAction::Reassigned)
    }
}

/// Check if ptr_name appears as an argument in an argument_list.
fn arg_list_contains_identifier(args: &Node, source: &str, name: &str) -> bool {
    for arg in args.child_nodes() {
        if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
            if subtree_contains_identifier(&arg, source, name) {
                return true;
            }
        }
    }
    false
}

/// If `&ptr_name` (address-of, no further dereference) appears as a
/// top-level argument in an argument_list -- the output-param call idiom --
/// return its zero-based parameter index (punctuation tokens excluded from
/// the count), so callers can look it up against a callee's `FunctionSummary`.
fn address_of_arg_index(args: &Node, source: &str, name: &str) -> Option<usize> {
    let mut idx = 0;
    for arg in args.child_nodes() {
        if matches!(arg.kind(), "(" | ")" | ",") {
            continue;
        }
        if arg.kind() == "pointer_expression" {
            let is_address_of = arg
                .child_by_field_name("operator")
                .map(|op| get_node_text(&op, source) == "&")
                .unwrap_or(false);
            if is_address_of {
                if let Some(operand) = arg.child_by_field_name("argument") {
                    if compact(get_node_text(&operand, source)) == name {
                        return Some(idx);
                    }
                }
            }
        }
        idx += 1;
    }
    None
}

/// Extract the declared variable name from a declaration node.
/// Handles: `int x`, `char *p`, `int *p = malloc(...)`, etc.
fn find_declarator_name(decl: &Node, source: &str) -> Option<String> {
    for child in decl.child_nodes() {
        match child.kind() {
            "init_declarator" => {
                // init_declarator has declarator as first field
                if let Some(d) = child.child_by_field_name("declarator") {
                    return extract_identifier_from_declarator(&d, source);
                }
            }
            "pointer_declarator" | "array_declarator" | "identifier" => {
                return extract_identifier_from_declarator(&child, source);
            }
            _ => {}
        }
    }
    None
}

/// Drill into nested declarators (pointer_declarator, array_declarator) to find the identifier.
fn extract_identifier_from_declarator(node: &Node, source: &str) -> Option<String> {
    let name = ast_utils::get_identifier_from_declarator(node, source);
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Find the basic block containing the given byte offset.
fn find_block_containing(
    cfg: &FunctionCfg,
    byte_offset: usize,
) -> Option<&crate::analyze::cfg::BasicBlock> {
    // First try statement-level containment (more precise)
    for block in &cfg.blocks {
        for &(start, end) in &block.statements {
            if byte_offset >= start && byte_offset < end {
                return Some(block);
            }
        }
    }
    // Fallback to block byte range
    cfg.blocks.iter().find(|block| {
        block.byte_range.0 > 0
            && byte_offset >= block.byte_range.0
            && byte_offset < block.byte_range.1
    })
}
