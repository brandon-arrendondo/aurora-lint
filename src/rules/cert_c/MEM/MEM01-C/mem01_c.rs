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
//! path that ends the process (`exit()`) escapes nothing either. Handing the
//! object to a function the file defines whose body never reads that member is
//! not an escape (`free(c->ssl); engine_deinit(c); free(c);`). The calls
//! that free are `free`, C23 `free_sized` / `free_aligned_sized` and a
//! project-declared deallocator.

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::{self as cfg_mod, FunctionCfg};
use crate::analyze::check_macros::{collect_macro_definitions, MacroDefinition};
use crate::analyze::context::ScopedTable;
use crate::analyze::context::{IncludeClosure, ProjectContext, VisibleTypes};
use crate::analyze::dataflow::find_node_at_range;
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::points_to::{lvalue_of, LValue};
use crate::analyze::prescan::ANONYMOUS_UNION_KEY;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::call_roles;
use crate::utility::cert_c::clearing_extent::cleared_extent;
use crate::utility::cert_c::node_children::NodeChildren;
use crate::utility::cert_c::pp_tokens::{lex_replacement_list, PpKind, KEYWORDS};
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
    /// Every scanned file's function-like macro definitions, by name, with the
    /// files that make them: a call spelled as one the translation unit
    /// includes is a macro expansion, not a call to a project function that
    /// shares the name.
    function_macro_arms:
        RefCell<Arc<HashMap<String, Vec<crate::analyze::macro_expand::ProjectMacroArm>>>>,
    /// The include graph, to find what the file may include.
    include_edges: RefCell<Arc<HashMap<String, Vec<String>>>>,
    /// The file being scanned.
    file_path: RefCell<std::path::PathBuf>,
    /// Its real path, as the include closure spells it.
    own_file: RefCell<Arc<str>>,
    /// The files the scanned file may include (`scan` builds it).
    include_closure: RefCell<Arc<IncludeClosure>>,
    /// The `#define`s and `#undef`s of each name in the file being scanned, in
    /// order, as (byte offset, whether it leaves a function-like macro in
    /// force): the one in force at a call decides what the call is.
    own_function_macros: RefCell<Arc<MacroDirectives>>,
    /// What the scanned files and headers declare, for reading a callee the
    /// way it compiles rather than by this file's text alone.
    headers: RefCell<HeaderTables>,
}

/// The project tables a callee of the destructor exemption is read against
/// besides the file: project headers are scanned but not expanded, so a macro,
/// object or union they declare is in force in the callee without appearing
/// in the file.
#[derive(Clone, Default)]
struct HeaderTables {
    /// Every `#define` of every scanned file and header, by name. Which file
    /// makes one is not recorded, so a definition other than a function-like
    /// macro counts wherever its name is used; a function-like one counts
    /// through `function_macro_arms`, which says which headers make it.
    macro_definitions: Arc<HashMap<String, Vec<MacroDefinition>>>,
    /// Every file-scope object (and enumeration constant) the scanned files
    /// and headers declare.
    global_object_names: Arc<HashSet<String>>,
    /// The struct and typedef tables as the file sees them.
    types: VisibleTypes,
}

/// A name's `#define`s and `#undef`s in a file, in order, as (byte offset,
/// whether it leaves a function-like macro in force).
type MacroDirectives = HashMap<String, Vec<(usize, bool)>>;

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
    /// `Mem01C::function_macro_arms`, `Mem01C::include_closure` and
    /// `Mem01C::own_function_macros`.
    function_macro_arms: Arc<HashMap<String, Vec<crate::analyze::macro_expand::ProjectMacroArm>>>,
    include_closure: Arc<IncludeClosure>,
    own_function_macros: Arc<MacroDirectives>,
    /// `Mem01C::headers`.
    headers: HeaderTables,
    /// The real path of the file being scanned, which its include closure
    /// contains: its own definitions are read by offset, not by that.
    own_file: Arc<str>,
}

impl AddressOfCallContext {
    /// Whether a call at byte `at` spelled `callee` is a function-like macro
    /// invocation: the last `#define` or `#undef` of the name in this file
    /// before the call says so; failing that, a definition in a file this one
    /// may include. A header the translation unit never reaches, or another
    /// `.c` file's private macro, is no definition of the callee here
    /// (ADR-0006).
    fn is_macro_call(&self, callee: &str, at: usize) -> bool {
        let in_force_here = self
            .own_function_macros
            .get(callee)
            .and_then(|events| events.iter().rev().find(|(offset, _)| *offset < at));
        if let Some(&(_, defined)) = in_force_here {
            return defined;
        }
        self.function_macro_arms.get(callee).is_some_and(|entries| {
            entries.iter().any(|e| {
                e.files
                    .iter()
                    .any(|f| **f != *self.own_file && self.include_closure.may_include(f))
            })
        })
    }

    /// Whether the definitions of `file` may be in force in this translation
    /// unit: a header it may include, or any header when the include graph
    /// does not say what it includes (a closure that is known always holds
    /// the file itself). Unlike [`Self::is_macro_call`], unknown counts: the
    /// destructor exemption clears a finding, so what it cannot rule out it
    /// must assume.
    fn header_in_reach(&self, file: &str) -> bool {
        *file != *self.own_file
            && ((self.include_closure.files.is_empty() && !self.include_closure.any)
                || self.include_closure.may_include(file))
    }

    /// Whether `name` may be a macro where a callee's body compiles: one this
    /// file defines (`own`), a function-like one a header in reach defines,
    /// or one any scanned file defines otherwise than as a function-like
    /// macro (see [`HeaderTables::macro_definitions`]).
    fn may_be_macro(&self, name: &str, own: &HashMap<String, Vec<MacroDefinition>>) -> bool {
        own.contains_key(name)
            || self
                .headers
                .macro_definitions
                .get(name)
                .is_some_and(|definitions| {
                    definitions
                        .iter()
                        .any(|d| !matches!(d, MacroDefinition::Function { .. }))
                })
            || self.function_macro_arms.get(name).is_some_and(|entries| {
                entries
                    .iter()
                    .any(|e| e.files.iter().any(|f| self.header_in_reach(f)))
            })
    }
}

impl Mem01C {
    pub fn new() -> Self {
        Self {
            function_cfgs: RefCell::new(HashMap::new()),
            cross_file_summaries: RefCell::default(),
            read_only_params: RefCell::default(),
            freeing_wrappers: RefCell::default(),
            defined_functions: RefCell::default(),
            function_macro_arms: RefCell::default(),
            include_edges: RefCell::default(),
            file_path: RefCell::default(),
            own_file: RefCell::new(Arc::from("")),
            include_closure: RefCell::default(),
            own_function_macros: RefCell::default(),
            headers: RefCell::default(),
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

    fn set_file_path(&self, path: &std::path::Path) {
        *self.file_path.borrow_mut() = path.to_path_buf();
        *self.own_file.borrow_mut() =
            Arc::from(crate::analyze::compile_commands::real_path(path).as_str());
    }

    fn set_function_cfgs(&self, cfgs: &HashMap<usize, FunctionCfg>) {
        *self.function_cfgs.borrow_mut() = cfgs.clone();
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.cross_file_summaries.borrow_mut() = context.function_summaries.clone();
        *self.read_only_params.borrow_mut() = Arc::new(self.build_read_only_params());
        *self.freeing_wrappers.borrow_mut() = Arc::new(self.build_freeing_wrappers());
        *self.function_macro_arms.borrow_mut() = Arc::clone(&context.function_macro_arms);
        *self.include_edges.borrow_mut() = Arc::clone(&context.include_edges);
        {
            let mut headers = self.headers.borrow_mut();
            headers.macro_definitions = Arc::clone(&context.macro_definitions);
            headers.global_object_names = Arc::clone(&context.global_object_names);
        }
        *self.defined_functions.borrow_mut() = Arc::new(
            self.cross_file_summaries
                .borrow()
                .iter()
                .map(|(name, _)| name.clone())
                .collect(),
        );
    }

    fn set_visible_types(&self, types: &VisibleTypes) {
        self.headers.borrow_mut().types = types.clone();
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        *self.own_function_macros.borrow_mut() = Arc::new(function_macro_offsets(source));
        *self.include_closure.borrow_mut() = Arc::new(IncludeClosure::of_scan(
            &self.include_edges.borrow(),
            &self.file_path.borrow(),
        ));
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
            function_macro_arms: Arc::clone(&self.function_macro_arms.borrow()),
            include_closure: Arc::clone(&self.include_closure.borrow()),
            own_function_macros: Arc::clone(&self.own_function_macros.borrow()),
            headers: self.headers.borrow().clone(),
            own_file: Arc::clone(&self.own_file.borrow()),
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

/// Each name `source` defines or undefines as a macro, with its directives in
/// order: (byte offset, whether it leaves a function-like macro in force). An
/// object-like `#define` and an `#undef` leave none.
fn function_macro_offsets(source: &str) -> MacroDirectives {
    let mut out = MacroDirectives::new();
    let mut offset = 0;
    for line in source.split_inclusive('\n') {
        let directive = line.trim_start().strip_prefix('#').map(str::trim_start);
        let defines = directive
            .and_then(|d| d.strip_prefix("define"))
            .filter(|r| r.starts_with([' ', '\t']));
        let undefines = directive
            .and_then(|d| d.strip_prefix("undef"))
            .filter(|r| r.starts_with([' ', '\t']));
        if let Some(rest) = defines.or(undefines).map(str::trim_start) {
            let name_len = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            if name_len > 0 {
                let function_like = defines.is_some() && rest[name_len..].starts_with('(');
                out.entry(rest[..name_len].to_string())
                    .or_default()
                    .push((offset, function_like));
            }
        }
        offset += line.len();
    }
    out
}

/// The arguments a call passes in the positions its callee's summary frees.
fn wrapper_freed_arguments<'t>(
    call: &Node<'t>,
    source: &str,
    addr_ctx: &AddressOfCallContext,
) -> Option<Vec<Node<'t>>> {
    // The callee must name the function, not a parameter or local spelled
    // the same (ADR-0006).
    let callee = crate::analyze::noreturn::called_function_name(call, source)?;
    let positions = addr_ctx.freeing_wrappers.get(&callee)?;
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
            .and_then(|c| crate::analyze::noreturn::called_function_name(&c, source))
            .is_some_and(|name| {
                matches!(
                    name.as_str(),
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
            // A callee that designates an object (a function-pointer
            // parameter) or a function-like macro of this file is not the
            // project function of the same spelling (ADR-0006).
            (hands_container && !callee_leaves_member_alone(&call, source, site, addr_ctx))
                || (site.global
                    && crate::analyze::noreturn::called_function_name(&call, source).is_some_and(
                        |callee| {
                            addr_ctx.defined_functions.contains(&callee)
                                && !addr_ctx.is_macro_call(&callee, call.start_byte())
                        },
                    ))
        })
}

/// Whether `call` hands the object the freed member lives in to a function this
/// file defines whose body provably leaves the member alone: the destructor
/// idiom, `free(c->ssl); engine_deinit(c); free(c);`. The callee's parameter
/// may be dereferenced for other fields, compared with null or passed to a
/// deallocator; any other use of it (a read of the member, passing it on,
/// returning it, dereferencing it as a whole, a local of the same name) is
/// taken as a read, as is any use of a name that may be a macro where the callee
/// compiles as a field name, or as an operand unless its expansion is proven to
/// name nothing a read goes through ([`CalleeScope::expansion_names_no_read`]),
/// a field that may share storage with the
/// member and any object declared at file scope (the caller may have stored the
/// object there). Project headers are scanned but not expanded, so their
/// macros, objects and structs count with the file's own ([`HeaderTables`]).
/// A definition under a conditional counts only where the call sits in the
/// arm's own span or every arm of the chain defines the callee. A callee with no single
/// body in this file or a macro is not
/// proven, so the call still counts as handing the dangling value on. A member
/// path is followed by its first field: `c->list.head` handed over as `c` is
/// read by a callee only through `c->list.head` or a prefix of it, and a callee
/// with one definition in each arm of a conditional must pass in every arm.
fn callee_leaves_member_alone(
    call: &Node,
    source: &str,
    site: &FreeSite,
    addr_ctx: &AddressOfCallContext,
) -> bool {
    let Some(callee) = crate::analyze::noreturn::called_function_name(call, source) else {
        return false;
    };
    if addr_ctx.is_macro_call(&callee, call.start_byte()) {
        return false;
    }
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let args: Vec<Node> = arguments
        .named_children(&mut arguments.walk())
        .filter(|a| a.kind() != "comment")
        .collect();
    // The one argument that is a container of the member, and the field the
    // callee would reach the member through: `pPhrase->doclist.aAll` handed
    // over as `pPhrase` is reached through `doclist`.
    let handed: Vec<(usize, &str)> = args
        .iter()
        .enumerate()
        .filter_map(|(i, a)| {
            let text = compact(get_node_text(&strip_parens_and_casts(a), source));
            site.containers
                .iter()
                .find(|c| **c == text)
                .map(|c| (i, c.as_str()))
        })
        .collect();
    let [(position, container)] = handed.as_slice() else {
        return false;
    };
    // Only a plain variable is followed into the callee, and the container
    // must not appear in another argument as well.
    if container.contains(['.', '>', '[', '(', '*'])
        || args
            .iter()
            .enumerate()
            .any(|(i, a)| i != *position && mentions_name(a, container, source))
    {
        return false;
    }
    let Some(field) = site
        .key
        .strip_prefix(container)
        .and_then(|rest| rest.strip_prefix("->").or_else(|| rest.strip_prefix('.')))
        .filter(|f| !f.is_empty())
    else {
        return false;
    };
    let mut root = *call;
    while let Some(p) = root.parent() {
        root = p;
    }
    // A definition under `#if` is no direct child of the file. One in a region
    // the file proves dead never compiles, so it is no body for the call.
    let dead = crate::analyze::dead_regions::DeadRegions::of(source);
    let definitions: Vec<Node> = query::find_descendants_of_kind(root, "function_definition")
        .into_iter()
        .filter(|f| function_definition_name(f, source).as_deref() == Some(callee.as_str()))
        .filter(|f| !dead.contains_node(f))
        .collect();
    if definitions.is_empty() {
        return false;
    }
    // A definition under a conditional leaves builds without it: it is a body
    // for the call only where the call sits in the arm that holds it, or every
    // arm of the chain defines the callee.
    if !definitions
        .iter()
        .all(|d| definition_reaches_call(d, call, &definitions, source))
    {
        return false;
    }
    let scope = CalleeScope {
        macros: collect_macro_definitions(source),
        unions: union_field_sets(root, source),
        globals: file_scope_variables(root, source),
        ctx: addr_ctx,
    };
    // Every definition, for one in each arm of a conditional.
    definitions.iter().all(|definition| {
        let Some(params) = ast_utils::get_function_parameters(definition, source) else {
            return false;
        };
        let declared = parameter_declarations(definition);
        // The name and the type must come from the same declaration.
        if declared.len() != params.len() {
            return false;
        }
        let (Some(_), Some(param_type), Some(body)) = (
            params.get(*position),
            declared
                .get(*position)
                .and_then(|d| d.child_by_field_name("type"))
                .map(|t| get_node_text(&t, source)),
            definition.child_by_field_name("body"),
        ) else {
            return false;
        };
        let parameters: Vec<&str> = params.iter().map(|(name, _)| name.as_str()).collect();
        parameter_never_reads_member(
            &body,
            &parameters,
            *position,
            param_type,
            field,
            source,
            &scope,
        )
    })
}

/// The `parameter_declaration`s of a function definition, in order.
fn parameter_declarations<'t>(definition: &Node<'t>) -> Vec<Node<'t>> {
    let mut declarator = definition.child_by_field_name("declarator");
    while let Some(d) = declarator.filter(|d| d.kind() != "function_declarator") {
        declarator = d.child_by_field_name("declarator");
    }
    declarator
        .and_then(|d| d.child_by_field_name("parameters"))
        .map(|list| {
            list.named_children(&mut list.walk())
                .filter(|p| p.kind() == "parameter_declaration")
                .collect()
        })
        .unwrap_or_default()
}

/// What a callee's body is read against besides its own text.
struct CalleeScope<'c> {
    /// Every macro the file defines, in any arm and at any depth, with its
    /// definitions. A name of one used in the callee may expand to a read of
    /// the parameter or the member, so such a callee is not proven unless
    /// each definition is object-like and its expansion names nothing a read
    /// could go through ([`Self::expansion_names_no_read`]); so may a macro a
    /// header defines ([`AddressOfCallContext::may_be_macro`]).
    macros: HashMap<String, Vec<MacroDefinition>>,
    /// The field names that share storage, one set per union the file
    /// declares, anonymous members flattened in. A union a header declares is
    /// found by resolving the aggregate's type instead ([`may_share_storage`]).
    unions: Vec<HashSet<String>>,
    /// Every object declared at file scope: the caller may have stored the
    /// object in one for the callee to read. So may an object a header
    /// declares ([`HeaderTables::global_object_names`]).
    globals: HashSet<String>,
    ctx: &'c AddressOfCallContext,
}

impl CalleeScope<'_> {
    /// Whether the macro `name`, used as an operand in the callee, expands to
    /// nothing a read of the member could go through, read as if its
    /// replacement list were written in place: every definition, the file's
    /// and every scanned file's, is object-like (a function-like or
    /// unreadable one, a token paste among them, is not proven), and every
    /// identifier it names is known to hold nothing: a keyword, a type name
    /// (a tag, or a typedef the tables resolve), a field selected off
    /// something in the list, or a macro that passes in turn. Anything else
    /// is a read: a name no table knows may be an object declared where the
    /// scan does not see it, such as by another macro's expansion; so is one
    /// of `reads` (the callee's parameters and own declarations, and the
    /// member's field names, in any position), a call, a function the
    /// project defines (it may read an object the caller stored the object
    /// in) and a field of something outside the list (one starting with `->`
    /// or `.`). `expanding` holds the macros being expanded: one that names
    /// itself again stays an unknown name.
    fn expansion_names_no_read(
        &self,
        name: &str,
        reads: &HashSet<&str>,
        expanding: &mut HashSet<String>,
    ) -> bool {
        if !expanding.insert(name.to_string()) {
            return false;
        }
        let passes = self.definitions_name_no_read(name, reads, expanding);
        expanding.remove(name);
        passes
    }

    fn definitions_name_no_read(
        &self,
        name: &str,
        reads: &HashSet<&str>,
        expanding: &mut HashSet<String>,
    ) -> bool {
        let in_reach_function_like =
            self.ctx
                .function_macro_arms
                .get(name)
                .is_some_and(|entries| {
                    entries
                        .iter()
                        .any(|e| e.files.iter().any(|f| self.ctx.header_in_reach(f)))
                });
        let definitions: Vec<&MacroDefinition> = self
            .macros
            .get(name)
            .into_iter()
            .flatten()
            .chain(
                self.ctx
                    .headers
                    .macro_definitions
                    .get(name)
                    .into_iter()
                    .flatten(),
            )
            .collect();
        if in_reach_function_like || definitions.is_empty() {
            return false;
        }
        let types = &self.ctx.headers.types;
        definitions.iter().all(|definition| {
            let MacroDefinition::Object { body } = definition else {
                return false;
            };
            let tokens = lex_replacement_list(body, false);
            if tokens.first().is_some_and(|t| t.is("->") || t.is(".")) {
                return false;
            }
            tokens
                .iter()
                .enumerate()
                .all(|(i, token)| match token.kind {
                    PpKind::Identifier => {
                        let word: &str = &token.text;
                        let after =
                            |p: &[&str]| i > 0 && p.iter().any(|p| tokens[i - 1].text == *p);
                        let keyword = KEYWORDS.contains(&word)
                            || matches!(word, "true" | "false" | "nullptr");
                        let called = !keyword && tokens.get(i + 1).is_some_and(|t| t.is("("));
                        if reads.contains(word)
                            || called
                            || self.ctx.defined_functions.contains(word)
                        {
                            return false;
                        }
                        keyword
                            || after(&["->", ".", "struct", "union", "enum"])
                            || types.typedef_types.contains_key(word)
                            || types.struct_typedef_aliases.contains_key(word)
                            || (self.ctx.may_be_macro(word, &self.macros)
                                && self.expansion_names_no_read(word, reads, expanding))
                    }
                    PpKind::Other => false,
                    _ => !token.is("##") && !token.is("#"),
                })
        })
    }

    /// Whether `ident`, an identifier of the callee's body, may name an
    /// object outside the callee: one the file declares at file scope, or one
    /// a header declares that no declaration in the file binds it to.
    fn names_outside_object(&self, ident: &Node, source: &str) -> bool {
        let name = get_node_text(ident, source);
        self.globals.contains(name)
            || (self.ctx.headers.global_object_names.contains(name)
                && ast_utils::resolve_identifier_declarator(ident, name, source).is_none())
    }
}

const CONDITIONAL_KINDS: [&str; 5] = [
    "preproc_if",
    "preproc_ifdef",
    "preproc_elif",
    "preproc_elifdef",
    "preproc_else",
];

/// The `#if` chain arms around `node`, innermost first; an include guard is no
/// alternative and is left out. tree-sitter nests an `#elif` or `#else` arm
/// inside the arm before it, as its `alternative`, so what lies in the later
/// arm lies in the earlier one's node but not in its own span: the earlier arm
/// is not around it.
fn enclosing_arms<'a>(node: &Node<'a>, source: &str) -> Vec<Node<'a>> {
    let mut arms = Vec::new();
    let mut current = *node;
    while let Some(parent) = current.parent() {
        if CONDITIONAL_KINDS.contains(&parent.kind())
            && parent.child_by_field_name("alternative") != Some(current)
            && !ast_utils::is_include_guard(&parent, source)
        {
            arms.push(parent);
        }
        current = parent;
    }
    arms
}

/// Whether the call can only be built with `definition` in the file: every arm
/// around the definition also encloses the call, or the outermost arm chain
/// the call is outside of defines the callee in each of its arms.
fn definition_reaches_call(
    definition: &Node,
    call: &Node,
    definitions: &[Node],
    source: &str,
) -> bool {
    let around_call = enclosing_arms(call, source);
    let outside: Vec<Node> = enclosing_arms(definition, source)
        .into_iter()
        .filter(|arm| !around_call.iter().any(|c| c.id() == arm.id()))
        .collect();
    let Some(outermost) = outside.last() else {
        return true;
    };
    // The head of the chain the outermost arm belongs to.
    let mut head = *outermost;
    while let Some(parent) = head.parent() {
        if CONDITIONAL_KINDS.contains(&parent.kind())
            && parent.child_by_field_name("alternative") == Some(head)
        {
            head = parent;
        } else {
            break;
        }
    }
    chain_defines_in_every_arm(&head, definitions, source)
}

/// Whether each arm of the chain starting at `head`, an `#else` arm last,
/// holds a definition of its own or a nested chain that does.
fn chain_defines_in_every_arm(head: &Node, definitions: &[Node], source: &str) -> bool {
    let mut arm = Some(*head);
    let mut has_else = false;
    while let Some(current) = arm {
        has_else = current.kind() == "preproc_else";
        let holds = definitions.iter().any(|d| {
            enclosing_arms(d, source)
                .first()
                .is_some_and(|inner| inner.id() == current.id())
        }) || nested_chain_heads(&current, source)
            .iter()
            .any(|nested| chain_defines_in_every_arm(nested, definitions, source));
        if !holds {
            return false;
        }
        arm = current.child_by_field_name("alternative");
    }
    has_else
}

/// The `#if` chains written directly in `arm` (not in a chain nested deeper).
fn nested_chain_heads<'a>(arm: &Node<'a>, source: &str) -> Vec<Node<'a>> {
    ["preproc_if", "preproc_ifdef"]
        .iter()
        .flat_map(|kind| query::find_descendants_of_kind(*arm, kind))
        .filter(|n| n.id() != arm.id())
        .filter(|n| {
            enclosing_arms(n, source)
                .first()
                .is_some_and(|inner| inner.id() == arm.id())
        })
        .collect()
}

/// The field names declared in each union of the file. A member that is itself
/// an anonymous struct or union lives in the same storage, so its fields join
/// the set (more than needed for an anonymous struct, which only errs toward a
/// read).
fn union_field_sets(root: Node, source: &str) -> Vec<HashSet<String>> {
    fn collect(body: &Node, source: &str, out: &mut HashSet<String>) {
        for field in body
            .named_children(&mut body.walk())
            .filter(|f| f.kind() == "field_declaration")
        {
            for declarator in field.children_by_field_name("declarator", &mut field.walk()) {
                if let Some(name) =
                    query::find_first_descendant(declarator, |n| n.kind() == "field_identifier")
                        .or_else(|| (declarator.kind() == "field_identifier").then_some(declarator))
                {
                    out.insert(get_node_text(&name, source).to_string());
                }
            }
            if let Some(inner) = field
                .child_by_field_name("type")
                .filter(|t| matches!(t.kind(), "struct_specifier" | "union_specifier"))
                .and_then(|t| t.child_by_field_name("body"))
            {
                if field
                    .children_by_field_name("declarator", &mut field.walk())
                    .next()
                    .is_none()
                {
                    collect(&inner, source, out);
                }
            }
        }
    }
    query::find_descendants_of_kind(root, "union_specifier")
        .into_iter()
        .filter_map(|u| u.child_by_field_name("body"))
        .map(|body| {
            let mut fields = HashSet::new();
            collect(&body, source, &mut fields);
            fields
        })
        .collect()
}

/// Every object the file declares at file scope (a function or a typedef is
/// none).
fn file_scope_variables(root: Node, source: &str) -> HashSet<String> {
    ast_utils::top_level_items(root)
        .filter(|item| item.kind() == "declaration")
        .filter(|item| {
            !item.named_children(&mut item.walk()).any(|c| {
                c.kind() == "storage_class_specifier" && get_node_text(&c, source) == "typedef"
            })
        })
        .flat_map(|item| {
            item.children_by_field_name("declarator", &mut item.walk())
                .map(|d| {
                    if d.kind() == "init_declarator" {
                        d.child_by_field_name("declarator").unwrap_or(d)
                    } else {
                        d
                    }
                })
                .filter(|d| {
                    query::find_first_descendant(*d, |n| n.kind() == "function_declarator")
                        .is_none()
                })
                .map(|d| ast_utils::get_identifier_from_declarator(&d, source))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn mentions_name(node: &Node, name: &str, source: &str) -> bool {
    query::find_first_descendant(*node, |n| {
        n.kind() == "identifier" && get_node_text(&n, source) == name
    })
    .is_some()
}

fn function_definition_name(function: &Node, source: &str) -> Option<String> {
    let mut declarator = function.child_by_field_name("declarator")?;
    while declarator.kind() != "function_declarator" {
        declarator = declarator.child_by_field_name("declarator")?;
    }
    let name = ast_utils::get_identifier_from_declarator(&declarator, source);
    (!name.is_empty()).then_some(name)
}

/// Whether, within `body`, every use of the parameter at `position` of
/// `parameters`, `param`, is one that cannot read `param->field`: a `->`
/// access of another field, a null test, or the freed argument of a
/// deallocator call.
fn parameter_never_reads_member(
    body: &Node,
    parameters: &[&str],
    position: usize,
    param_type: &str,
    field: &str,
    source: &str,
    scope: &CalleeScope,
) -> bool {
    let Some(&param) = parameters.get(position) else {
        return false;
    };
    let locals: Vec<String> = query::find_descendants_of_kind(*body, "declaration")
        .into_iter()
        .flat_map(|d| {
            d.children_by_field_name("declarator", &mut d.walk())
                .map(|declarator| {
                    let declarator = if declarator.kind() == "init_declarator" {
                        declarator
                            .child_by_field_name("declarator")
                            .unwrap_or(declarator)
                    } else {
                        declarator
                    };
                    ast_utils::get_identifier_from_declarator(&declarator, source)
                })
                .collect::<Vec<_>>()
        })
        .collect();
    // A local or nested declaration of the same name makes the uses
    // ambiguous.
    if locals.iter().any(|l| l == param) {
        return false;
    }
    let declared_names: Vec<String> = parameters
        .iter()
        .map(|p| p.to_string())
        .chain(locals)
        .collect();
    let member: Vec<&str> = field
        .split(['-', '.', '>'])
        .filter(|f| !f.is_empty())
        .collect();
    // A macro used as a field name may expand to the member, and one used
    // as an operand to a read of the parameter or the member, unless its
    // expansion is proven to name nothing such a read goes through; any
    // object of the file or its headers may hold the object.
    let reads: HashSet<&str> = member
        .iter()
        .copied()
        .chain(declared_names.iter().map(String::as_str))
        .collect();
    let hidden_read = query::find_descendants_of_kind(*body, "field_identifier")
        .into_iter()
        .any(|n| {
            scope
                .ctx
                .may_be_macro(get_node_text(&n, source), &scope.macros)
        })
        || query::find_descendants_of_kind(*body, "identifier")
            .into_iter()
            .any(|n| {
                let name = get_node_text(&n, source);
                scope.ctx.may_be_macro(name, &scope.macros)
                    && !scope.expansion_names_no_read(name, &reads, &mut HashSet::new())
            })
        || query::find_descendants_of_kind(*body, "identifier")
            .into_iter()
            .any(|n| scope.names_outside_object(&n, source));
    if hidden_read {
        return false;
    }
    query::find_descendants_of_kind(*body, "identifier")
        .into_iter()
        .filter(|i| get_node_text(i, source) == param)
        .all(|ident| {
            let Some(parent) = ident.parent() else {
                return false;
            };
            match parent.kind() {
                "field_expression" => {
                    access_misses_member(&ident, &member, param_type, source, scope)
                }
                "argument_list" => parent
                    .parent()
                    .filter(|c| c.kind() == "call_expression")
                    .is_some_and(|c| freed_argument(&c, source).is_some_and(|a| a == ident)),
                "unary_expression" => get_node_text(&parent, source).starts_with('!'),
                "binary_expression" => {
                    parent
                        .child_by_field_name("operator")
                        .is_some_and(|op| matches!(get_node_text(&op, source), "==" | "!="))
                        && ["left", "right"].iter().any(|side| {
                            parent.child_by_field_name(side).is_some_and(|n| {
                                matches!(get_node_text(&n, source), "NULL" | "0" | "nullptr")
                            })
                        })
                }
                // Only the condition of a branch or loop: `return (p);`
                // hands the object on.
                "condition_clause" => parent
                    .parent()
                    .is_some_and(|g| g.kind().ends_with("_statement")),
                "parenthesized_expression" => parent.parent().is_some_and(|g| {
                    matches!(
                        g.kind(),
                        "if_statement" | "while_statement" | "do_statement"
                    ) && g.child_by_field_name("condition") == Some(parent)
                }),
                _ => false,
            }
        })
}

/// Whether the access chain that starts at `ident` (`p->a.b`, `p->a[i]`) names
/// a different field than `member` (`["a", "b"]`) at the first place the two
/// differ: neither is a prefix of the other, and the two fields are members of
/// a struct, not one storage. Only a `->` off the parameter itself, of type
/// `param_type`, is followed.
fn access_misses_member(
    ident: &Node,
    member: &[&str],
    param_type: &str,
    source: &str,
    scope: &CalleeScope,
) -> bool {
    let mut chain: Vec<String> = Vec::new();
    let mut current = *ident;
    while let Some(parent) = current.parent() {
        if parent.kind() != "field_expression"
            || parent.child_by_field_name("argument") != Some(current)
        {
            break;
        }
        let arrow = parent
            .child_by_field_name("operator")
            .is_some_and(|op| get_node_text(&op, source) == "->");
        if chain.is_empty() && !arrow {
            return false;
        }
        let Some(name) = parent.child_by_field_name("field") else {
            return false;
        };
        chain.push(get_node_text(&name, source).to_string());
        current = parent;
    }
    // `p->a[i]` and `(*p->a)` read `a`; the chain ends where the subscript
    // or dereference begins, which is a prefix of the member either way.
    // Only the first place the two paths differ matters, and not when the two
    // fields share storage.
    !chain.is_empty()
        && chain
            .iter()
            .zip(member)
            .position(|(accessed, wanted)| accessed != wanted)
            .is_some_and(|at| {
                let (accessed, wanted) = (&chain[at], member[at]);
                !scope
                    .unions
                    .iter()
                    .any(|u| u.contains(accessed) && u.contains(wanted))
                    && !may_share_storage(param_type, &member[..at], &scope.ctx.headers.types)
            })
}

/// Whether two fields of the aggregate reached from a parameter of type
/// `param_type` through `prefix` may share storage: that aggregate is a union,
/// or its declaration, the file's own or a header's, does not resolve to a
/// struct (ADR-0006: by declaration, not by a field's spelling).
fn may_share_storage(param_type: &str, prefix: &[&str], types: &VisibleTypes) -> bool {
    let mut aggregate = param_type.to_string();
    for field in prefix {
        let Some(next) = struct_fields(&aggregate, types).and_then(|fields| fields.get(*field))
        else {
            return true;
        };
        aggregate = next.clone();
    }
    struct_fields(&aggregate, types).is_none()
}

/// The field table of the struct a type spelling names (`struct conn`,
/// `const conn_t *`, or a typedef of a struct), or `None` for a union, an
/// aggregate with no name of its own, a struct with an anonymous union member
/// (whose members the table files as the struct's own) and a type no table
/// knows. The tables file only structs, never a union.
fn struct_fields<'t>(
    spelling: &str,
    types: &'t VisibleTypes,
) -> Option<&'t HashMap<String, String>> {
    let words: Vec<&str> = spelling
        .split(|c: char| c.is_whitespace() || c == '*')
        .filter(|w| !w.is_empty() && !matches!(*w, "const" | "volatile" | "restrict"))
        .collect();
    let name = match words.as_slice() {
        ["struct", tag] => *tag,
        [name] => types
            .struct_typedef_aliases
            .get(*name)
            .map_or(*name, String::as_str),
        _ => return None,
    };
    let has_anonymous_union = types
        .struct_field_shapes
        .get(name)
        .is_some_and(|shapes| shapes.contains_key(ANONYMOUS_UNION_KEY));
    if has_anonymous_union {
        return None;
    }
    types.struct_field_types.get(name)
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
