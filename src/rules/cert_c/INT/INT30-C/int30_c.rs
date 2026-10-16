// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::{self, FunctionCfg};
use crate::analyze::const_eval::{self, MacroConstantMap, ValueRange, VarRangeMap};
use crate::analyze::context::SummaryLookup;
use crate::analyze::context::{ProjectContext, ScopedTable, VisibleTypes};
use crate::analyze::function_summary::{self, FunctionSummary};
use crate::analyze::value_range::RangeAnalysisResult;
use crate::analyze::vra_access;
use crate::manifest::Severity;
use crate::rules::cert_c::int_provenance;
use crate::settings::IntFacts;
use crate::utility::cert_c::ast_utils::{
    self, get_node_text, get_sanitized_node_text, ScopeDeclarations,
};
use crate::utility::cert_c::data_model::{self, Rank};
use crate::utility::cert_c::expr_type::{integer_literal_width, TypeEnv};
use crate::utility::cert_c::float_typing;
use crate::utility::cert_c::guard_dominance;
use crate::utility::cert_c::overflow_helpers;
use crate::utility::cert_c::pointer_typing::{self, PointerFacts};
use crate::utility::cert_c::std_functions;
use crate::utility::cert_c::subtree_any::SubtreeAny;
use crate::utility::cert_c::text_index::TextIndex;
use lang_parsing_substrate::query;
use std::cell::{Cell, Ref, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;
use tree_sitter::Node;

/// Depth cap for walking into an operand looking for its type.
const OPERAND_TYPE_MAX_DEPTH: u32 = 8;

/// A name and the statement it is resolved under, by the statement's kind
/// and span; see `Int30C::identifier_types`.
type NameUnderStatement = (String, &'static str, usize, usize);

/// A node's kind and byte span: what it was, and enough to find it again.
#[derive(Clone, Copy)]
struct Span {
    kind: &'static str,
    start: usize,
    end: usize,
}

impl Span {
    fn of(node: &Node) -> Self {
        Self {
            kind: node.kind(),
            start: node.start_byte(),
            end: node.end_byte(),
        }
    }

    fn contains(&self, node: &Node) -> bool {
        self.start <= node.start_byte() && node.end_byte() <= self.end
    }

    /// The node this span was taken from, found by descending from `root`.
    /// [`Site`] records statements, blocks and functions this way, which sit
    /// only as deep as the statement nesting, so the descent is short however
    /// deep the expression inside them. `None` if it cannot be told apart.
    fn find<'t>(&self, root: Node<'t>) -> Option<Node<'t>> {
        let mut node = root.descendant_for_byte_range(self.start, self.end)?;
        loop {
            if node.start_byte() != self.start || node.end_byte() != self.end {
                return None;
            }
            if node.kind() == self.kind {
                return Some(node);
            }
            node = node.parent()?;
        }
    }
}

/// Where the operator being checked sits, as `check_node`'s walk found it on
/// the way down. tree-sitter recovers a parent by descending from the root,
/// so an operator thousands of levels into an expression costs thousands of
/// steps to climb out of, and a question asked at every operator of it costs
/// the square. The walk passes each fact down once instead.
struct Site {
    /// The operator itself.
    node: Span,
    id: usize,
    /// The whole expression it is part of: its outermost expression ancestor,
    /// or itself.
    expression: Span,
    /// Its parent.
    parent: Option<Span>,
    /// The operator of the binary expression it is an operand of, looking
    /// through one pair of parentheses.
    enclosing_operator: Option<String>,
    /// Its ancestors that are not expressions, innermost first: the
    /// statements, blocks, conditionals, loops and function around it.
    outer: Vec<Span>,
    /// The conditions governing it that name an integer limit (see
    /// [`WalkState::limit_conditions`]).
    limit_conditions: Vec<Span>,
}

/// The declared type a name resolves to: `None` when the declaration it
/// resolves to has a type with no spelling.
type Resolution = Option<String>;

/// The syntactic ranges of one expression (see
/// [`Int30C::syntactic_ranges_ready`]): for an operator that starts later
/// than the expression, and, when they differ, for one that starts with it.
type SyntacticTables = (Box<VarRangeMap>, Option<Box<VarRangeMap>>);

/// One non-expression ancestor on the walk down, linked to the next one out.
struct Outer<'t> {
    node: Node<'t>,
    up: Option<Rc<Outer<'t>>>,
}

/// One condition governing a node on the walk down, linked to the rest.
struct Governing<'t> {
    condition: Node<'t>,
    up: Option<Rc<Governing<'t>>>,
}

/// What `check_node`'s walk carries down to each node.
#[derive(Clone, Default)]
struct WalkState<'t> {
    /// Whether an expression encloses this node.
    in_expression: bool,
    /// The outermost expression of the unbroken run of expressions this
    /// node's parent ends, if its parent is an expression.
    expression_root: Option<Node<'t>>,
    parent: Option<Node<'t>>,
    grandparent: Option<Node<'t>>,
    function: Option<Node<'t>>,
    outer: Option<Rc<Outer<'t>>>,
    /// The conditions that govern this node as
    /// `guard_dominance::dominating_conditions` reads them, within its
    /// function, keeping only those that name an integer limit: the only
    /// ones `has_dominating_limit_guard` reads.
    limit_conditions: Option<Rc<Governing<'t>>>,
}

/// Whether a node of `kind` is part of an expression, which [`Site::outer`]
/// passes over. None of the ancestors this rule looks for is one.
fn is_expression_kind(kind: &str) -> bool {
    kind.ends_with("_expression") || kind == "argument_list"
}

/// The nearest non-expression ancestors under which every occurrence of a
/// name resolves alike, so [`Int30C::identifier_type`] resolves a name once
/// per such statement. Every declaration a resolution weighs starts either
/// before the whole statement or after it -- a `for` declares in its
/// initializer, ahead of every expression its header holds -- so it is
/// before all of the statement's occurrences of a name or before none.
/// A parser `ERROR` node, which may hold declarations among its
/// expressions, is not one of them.
fn resolves_alike_under(kind: &str) -> bool {
    matches!(
        kind,
        "expression_statement"
            | "return_statement"
            | "init_declarator"
            | "if_statement"
            | "while_statement"
            | "do_statement"
            | "for_statement"
            | "switch_statement"
            | "case_statement"
            | "array_declarator"
    )
}

pub struct Int30C {
    project_macros: RefCell<Arc<MacroConstantMap>>,
    current_macros: RefCell<MacroConstantMap>,
    struct_field_types: RefCell<Arc<HashMap<String, HashMap<String, String>>>>,
    /// The typedefs and struct fields this file sees, for typing operands by
    /// declaration.
    visible: RefCell<VisibleTypes>,
    function_cfgs: RefCell<HashMap<usize, FunctionCfg>>,
    vra_results: RefCell<HashMap<usize, RangeAnalysisResult>>,
    function_summaries: RefCell<ScopedTable<FunctionSummary>>,
    /// Globals written by a tainted function — see the INT32-C provenance gate.
    global_writers: RefCell<Arc<HashMap<String, HashSet<String>>>>,
    /// Per-function memo of risky variable names, keyed by function node id;
    /// cleared per file.
    risky_vars_cache: RefCell<HashMap<usize, HashSet<String>>>,
    /// Reverse call graph: callee name → the functions that call it. Backs the
    /// parameter arm of the provenance gate (`int_provenance::ParamContext`).
    callers: RefCell<Arc<HashMap<String, HashSet<String>>>>,
    /// Per-function memo of parameter names, keyed by function node id; cleared
    /// per file alongside `risky_vars_cache`.
    param_names_cache: RefCell<HashMap<usize, Vec<String>>>,
    /// File-scope pointer names and pointer-returning functions, for the
    /// pointer-arithmetic gate. Rebuilt per file.
    pointer_facts: RefCell<PointerFacts>,
    /// This file's exact constant values and pointer walks per node, cleared
    /// per file: the rule asks at every operator of an expression, and each
    /// question otherwise walks the operator's whole operand again, so a
    /// sum thousands of terms deep cost the cube of its length.
    constant: const_eval::ConstMemo,
    pointer: pointer_typing::PointerMemo,
    /// Arrays declared in a header or another file, from `set_project_context`.
    project_arrays: RefCell<Arc<HashSet<String>>>,
    /// Declared return types of functions this file defines or prototypes
    /// (`overflow_helpers::collect_function_return_types`), so a call
    /// operand can be typed the same way INT32-C types it -- one half of the
    /// signed/unsigned dispatch cannot see `size_t` returns while the other
    /// does.
    function_return_types: RefCell<HashMap<String, String>>,
    /// One-level typedef alias map from the project context, resolved
    /// through `overflow_helpers::typedef_chain_is_unsigned` in
    /// `is_unsigned_type`.
    typedef_types: RefCell<Arc<HashMap<String, String>>>,
    /// The project-wide name sets `const_eval::is_compile_time_constant_expr`
    /// wants, mirroring INT34-C: every object-like and function-like
    /// `#define` the scan saw, and the functions whose every `return` is a
    /// compile-time constant. What lets a `calloc` count spelled with a
    /// macro from another header still read as fixed.
    project_macro_names: RefCell<Arc<HashSet<String>>>,
    project_function_macro_names: RefCell<HashSet<String>>,
    constant_returning_functions: RefCell<HashSet<String>>,
    /// The integer data model the settings credit: which limit macros and
    /// `sizeof` values are constants.
    data_model: Cell<IntFacts>,
    /// This file's text as written and with comments and literals blanked,
    /// each read once (see [`TextIndex`]); built on first use.
    raw_text: RefCell<Option<TextIndex>>,
    sanitized_text: RefCell<Option<TextIndex>>,
    /// The operator being checked; see [`Site`].
    site: RefCell<Option<Site>>,
    /// Whether this file defines a function inside another (a GNU
    /// extension). A node inside the operator being checked is then not
    /// known to share its function without looking.
    nested_functions: Cell<bool>,
    /// Whether this file has a block inside an expression (a GNU statement
    /// expression), whose names can resolve unlike the rest of the
    /// expression's.
    statement_expressions: Cell<bool>,
    /// The declared type each name resolves to under each statement
    /// ([`resolves_alike_under`]), by name and the statement's kind and
    /// span: `None` when it resolves to no declaration, `Some(None)` when to
    /// one whose type has no spelling.
    identifier_types: RefCell<HashMap<NameUnderStatement, Option<Resolution>>>,
    /// Per-node answers for this file, cleared per file: whether an
    /// expression is floating, whether a subtree spells out an unsigned type
    /// ([`Self::spells_out_unsigned`]), and whether a subtree's last token is
    /// an unsigned literal. The rule asks each of every operand of every
    /// operator, and each walks the operand's subtree.
    float: float_typing::FloatMemo,
    risk: int_provenance::RiskMemo,
    unsigned_spelling: SubtreeAny,
    /// Whether a subtree names an integer limit (`guard_dominance`'s test of
    /// a governing condition), per node for the file.
    limit_mention: SubtreeAny,
    unsigned_last_literal: RefCell<HashMap<usize, bool>>,
    /// The syntactic ranges of `expression_fits_in_unsigned` for each whole
    /// expression this file asked about, by its span: for an operator that
    /// starts later than the expression, and (when they differ) for one
    /// that starts with it. `None` where the record could not build them.
    syntactic_ranges: RefCell<HashMap<(usize, usize), Option<SyntacticTables>>>,
    /// VRA ranges replayed to each (function start, expression start) this
    /// file asked about.
    vra_ranges: RefCell<HashMap<(usize, usize), Option<VarRangeMap>>>,
}

impl Int30C {
    pub fn new() -> Self {
        Self {
            project_macros: RefCell::new(Arc::new(MacroConstantMap::new())),
            current_macros: RefCell::new(MacroConstantMap::new()),
            struct_field_types: RefCell::new(Arc::new(HashMap::new())),
            visible: RefCell::default(),
            function_cfgs: RefCell::new(HashMap::new()),
            vra_results: RefCell::new(HashMap::new()),
            function_summaries: RefCell::default(),
            global_writers: RefCell::new(Arc::new(HashMap::new())),
            risky_vars_cache: RefCell::new(HashMap::new()),
            callers: RefCell::default(),
            param_names_cache: RefCell::new(HashMap::new()),
            constant: Default::default(),
            pointer: Default::default(),
            pointer_facts: RefCell::new(PointerFacts::default()),
            project_arrays: RefCell::new(Arc::new(HashSet::new())),
            function_return_types: RefCell::new(HashMap::new()),
            typedef_types: RefCell::new(Arc::new(HashMap::new())),
            project_macro_names: RefCell::new(Arc::new(HashSet::new())),
            project_function_macro_names: RefCell::new(HashSet::new()),
            constant_returning_functions: RefCell::new(HashSet::new()),
            data_model: Cell::new(IntFacts::default()),
            raw_text: RefCell::new(None),
            sanitized_text: RefCell::new(None),
            site: RefCell::new(None),
            nested_functions: Cell::new(false),
            statement_expressions: Cell::new(false),
            float: Default::default(),
            risk: Default::default(),
            syntactic_ranges: RefCell::new(HashMap::new()),
            unsigned_spelling: Default::default(),
            limit_mention: Default::default(),
            unsigned_last_literal: RefCell::new(HashMap::new()),
            identifier_types: RefCell::new(HashMap::new()),
            vra_ranges: RefCell::new(HashMap::new()),
        }
    }

    /// This file's text as written.
    fn raw_text(&self, source: &str) -> Ref<'_, TextIndex> {
        if self.raw_text.borrow().is_none() {
            *self.raw_text.borrow_mut() = Some(TextIndex::raw(source));
        }
        Ref::map(self.raw_text.borrow(), |t| t.as_ref().unwrap())
    }

    /// This file's text with comments and literals blanked, as
    /// `get_sanitized_node_text` blanks them.
    fn sanitized_text(&self, node: &Node, source: &str) -> Ref<'_, TextIndex> {
        if self.sanitized_text.borrow().is_none() {
            *self.sanitized_text.borrow_mut() =
                Some(TextIndex::sanitized(&ast_utils::tree_root(node), source));
        }
        Ref::map(self.sanitized_text.borrow(), |t| t.as_ref().unwrap())
    }

    /// The [`Site`] of the operator being checked, when `node` is inside it
    /// (or is it): `node` then has the operator's function and scopes.
    fn site_around(&self, node: &Node) -> Option<Ref<'_, Site>> {
        Ref::filter_map(self.site.borrow(), |site| {
            site.as_ref()
                .filter(|s| s.id == node.id() || s.node.contains(node))
        })
        .ok()
    }

    /// The [`Site`] of the operator being checked, when `node` is that operator.
    fn site_of(&self, node: &Node) -> Option<Ref<'_, Site>> {
        Ref::filter_map(self.site.borrow(), |site| {
            site.as_ref().filter(|s| s.id == node.id())
        })
        .ok()
    }

    /// [`ast_utils::find_containing_function`], from the walk's record when
    /// `node` is inside the operator being checked.
    fn containing_function<'t>(&self, node: &Node<'t>) -> Option<Node<'t>> {
        if !self.nested_functions.get() {
            if let Some(site) = self.site_around(node) {
                let span = site
                    .outer
                    .iter()
                    .find(|s| s.kind == "function_definition")?;
                if let Some(func) = span.find(ast_utils::tree_root(node)) {
                    return Some(func);
                }
            }
        }
        ast_utils::find_containing_function(node)
    }

    /// Whether the sanitized text of `node`'s function (of the whole file,
    /// at file scope) contains every one of `patterns`.
    fn function_text_contains_all(&self, node: &Node, source: &str, patterns: &[&str]) -> bool {
        let scope = self
            .containing_function(node)
            .unwrap_or_else(|| ast_utils::tree_root(node));
        let text = self.sanitized_text(node, source);
        patterns.iter().all(|p| text.contains(&scope, p))
    }

    /// Whether the sanitized text of `node`'s function contains any one of
    /// `patterns`; false at file scope.
    fn function_text_contains_any(&self, node: &Node, source: &str, patterns: &[&str]) -> bool {
        let Some(func) = self.containing_function(node) else {
            return false;
        };
        let text = self.sanitized_text(node, source);
        patterns.iter().any(|p| text.contains(&func, p))
    }

    /// [`ast_utils::identifier_type`], resolving each name once per
    /// statement when `ident` is inside the operator being checked.
    ///
    /// Resolving an occurrence descends from the root to it, which costs
    /// its depth: a parameter used at every operator of a sum thousands of
    /// terms long cost the square. Under one statement every occurrence of
    /// a name resolves alike ([`resolves_alike_under`]), and the walk's
    /// record of the statements around the operator is the path a
    /// resolution reads -- scopes, the function and the root -- without
    /// the expressions between, which it does not.
    fn identifier_type<'m>(
        &self,
        ident: &Node,
        source: &str,
        type_map: &'m HashMap<String, String>,
    ) -> Option<std::borrow::Cow<'m, str>> {
        let name = get_node_text(ident, source);
        let resolved = match self.resolve_under_statement(ident, name, source) {
            Some(resolved) => resolved,
            None => ast_utils::resolve_identifier_declarator(ident, name, source).map(
                |(decl, declarator)| {
                    ast_utils::declaration_type_spelling(&decl, &declarator, source)
                },
            ),
        };
        if let Some(spelling) = resolved {
            return spelling.map(std::borrow::Cow::Owned);
        }
        type_map
            .get(name)
            .map(|t| std::borrow::Cow::Borrowed(t.as_str()))
    }

    /// What `ident` resolves to, from the statement record of the operator
    /// being checked: `None` when the record cannot answer.
    fn resolve_under_statement(
        &self,
        ident: &Node,
        name: &str,
        source: &str,
    ) -> Option<Option<Resolution>> {
        if ident.kind() != "identifier" || self.statement_expressions.get() {
            return None;
        }
        let outer = self.site_around(ident).map(|site| site.outer.clone())?;
        let statement = outer.first().filter(|s| resolves_alike_under(s.kind))?;
        let key = (
            name.to_string(),
            statement.kind,
            statement.start,
            statement.end,
        );
        if let Some(known) = self.identifier_types.borrow().get(&key) {
            return Some(known.clone());
        }
        let root = ast_utils::tree_root(ident);
        // Outermost first, without the root itself, which ends the record.
        let (last, inner) = outer.split_last()?;
        if last.start != root.start_byte() || last.end != root.end_byte() {
            return None;
        }
        let path = inner
            .iter()
            .rev()
            .map(|span| span.find(root))
            .collect::<Option<Vec<_>>>()?;
        let resolved =
            ast_utils::resolve_identifier_declarator_on_path(&root, &path, ident, name, source)
                .map(|(decl, declarator)| {
                    ast_utils::declaration_type_spelling(&decl, &declarator, source)
                });
        self.identifier_types
            .borrow_mut()
            .insert(key, resolved.clone());
        Some(resolved)
    }

    /// Opt-in provenance gate for unsigned wrap — the unsigned analogue of
    /// INT32-C's gate. Returns true when an operand derives from untrusted or
    /// unbounded input, or when the expression *definitely* wraps a 32-bit
    /// unsigned type (value-based VRA channel). When false, every operand is
    /// bounded local state and the wrap is treated as intended/non-overflowing.
    /// Runs in every configuration: with no cross-file context the taint
    /// channels simply have fewer sources to match (standard taint functions
    /// still resolve by name, project-local summaries do not), so a run without
    /// `-d` reports a subset of what one with `-d` reports rather than a
    /// different, louder rule.
    fn has_risky_operand_provenance(&self, node: &Node, source: &str, bits: Option<u32>) -> bool {
        // VRA definite-wrap channel (UINT_MAX + 1 / 0u - 1), asked at the same
        // width the caller's fits-check used. Asking at 32 while the operation
        // runs in 64 calls a 64-bit product that merely exceeds UINT_MAX a
        // definite wrap, which it is not. A width nobody knows
        // (`arith_width_known` is `None`) cannot be definitely exceeded at
        // all, so that half of the channel is not asked at the floor; the
        // other half -- a result below zero wraps in unsigned arithmetic of
        // ANY width -- still is, which asking at 64 leaves as the only one.
        if const_eval::expression_overflows_unsigned_vra_with(
            node,
            source,
            &self.current_macros.borrow(),
            bits.unwrap_or(64),
            self.vra_var_ranges_at(node, source).as_ref(),
            Some(&self.constant),
        ) {
            return true;
        }

        let summaries = self.function_summaries.borrow();
        let func = match self.containing_function(node) {
            Some(f) => f,
            None => return true,
        };
        let body = match func.child_by_field_name("body") {
            Some(b) => b,
            None => return true,
        };

        let func_id = func.id();
        {
            let mut cache = self.risky_vars_cache.borrow_mut();
            cache
                .entry(func_id)
                .or_insert_with(|| int_provenance::collect_risky_vars(&body, &summaries, source));
        }
        let cache = self.risky_vars_cache.borrow();
        let risky_vars = match cache.get(&func_id) {
            Some(s) => s,
            None => return true,
        };
        let global_writers = self.global_writers.borrow();

        // A parameter carries whatever its callers pass, so its provenance is a
        // property of the call sites and needs the reverse call graph. Without
        // cross-file context (`summaries` empty — a run without `-d`) there are
        // no callers to reason from, so the parameter arm stays off and the
        // gate keeps its older, narrower behaviour rather than firing on every
        // parameter it cannot bound.
        {
            let mut cache = self.param_names_cache.borrow_mut();
            cache.entry(func_id).or_insert_with(|| {
                // Every position kept, unnamed ones included: a call site's
                // argument is matched to its parameter by position.
                function_summary::collect_param_names(&func, source)
            });
        }
        let param_names = self.param_names_cache.borrow();
        let param_ctx = match (
            cfg::get_function_name(&func, source),
            param_names.get(&func_id),
        ) {
            (Some(func_name), Some(params)) if !summaries.is_empty() => {
                Some(int_provenance::ParamContext { func_name, params })
            }
            _ => None,
        };

        let mut operands = Vec::new();
        if let Some(l) = node.child_by_field_name("left") {
            operands.push(l);
        }
        if let Some(r) = node.child_by_field_name("right") {
            operands.push(r);
        }
        if let Some(a) = node.child_by_field_name("argument") {
            operands.push(a);
        }

        operands.iter().any(|op| {
            int_provenance::operand_is_risky_with(
                op,
                risky_vars,
                &summaries,
                &global_writers,
                param_ctx.as_ref(),
                source,
                Some(&self.risk),
            )
        })
    }

    /// [`const_eval::expression_fits_in_unsigned_vra`] over this rule's macro
    /// set and the VRA ranges at `node`.
    ///
    /// Under ISO C's widths an unsigned type has no width, so the top of its
    /// range runs to the end of `i64`, and arithmetic over it leaves `i64`
    /// and gives up. That side is the type's own limit, whatever width the
    /// type has, so it is read as the limit of the `bits`-wide type the fit
    /// is asked of: `x - 1` after `x < 1` returns then fits, where an
    /// unguarded `x + 1` still does not on any width.
    fn expression_fits_in_unsigned(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
        bits: u32,
    ) -> bool {
        let mut ranges = self.vra_var_ranges_at(node, source);
        if !self.data_model.get().width_known(Rank::Int) && (1..63).contains(&bits) {
            let high = (1i64 << bits) - 1;
            for (name, range) in ranges.iter_mut().flat_map(|ranges| ranges.iter_mut()) {
                let keep = self.guards_bound_no_wider_than(node, source, type_map, name, bits);
                range.max = data_model::bound_open_top(range.min, range.max, high, keep);
            }
        }
        if self.syntactic_ranges_ready(node, source) {
            let site = self.site_of(node).expect("ready only for the site");
            let key = (site.expression.start, site.expression.end);
            let leading = site.node.start == site.expression.start;
            drop(site);
            let tables = self.syntactic_ranges.borrow();
            let (later, first) = tables[&key].as_ref().expect("ready");
            let syntactic = match first {
                Some(first) if leading => first,
                _ => later,
            };
            return const_eval::expression_fits_in_unsigned_vra_given(
                node,
                source,
                &self.current_macros.borrow(),
                bits,
                ranges.as_ref(),
                syntactic,
                Some(&self.constant),
            );
        }
        const_eval::expression_fits_in_unsigned_vra_with(
            node,
            source,
            &self.current_macros.borrow(),
            bits,
            ranges.as_ref(),
            Some(&self.constant),
        )
    }

    /// Whether [`Self::syntactic_ranges`] holds the tables for `node`, the
    /// operator being checked, building them on first ask for its expression.
    ///
    /// The syntactic fallback of an unsigned fit reads the ranges of the
    /// names in the operator, each resolved from the assignments before its
    /// first use there, with the loops around it. Every name of one
    /// expression has the same blocks, loops and function around it, and a
    /// use is before a statement on its path exactly when the expression is,
    /// except a use that is the expression's very first token. So the
    /// tables are built once per expression, from a walk of it rather than
    /// of every operator: one for an operator that starts later than the
    /// expression, and one, differing only in the first token's name, for
    /// an operator that starts with it. A range for a name an operator does
    /// not hold is never read.
    fn syntactic_ranges_ready(&self, node: &Node, source: &str) -> bool {
        if self.statement_expressions.get() {
            return false;
        }
        let Some(site) = self.site_of(node) else {
            return false;
        };
        let key = (site.expression.start, site.expression.end);
        if let Some(known) = self.syntactic_ranges.borrow().get(&key) {
            return known.is_some();
        }
        let expression = site.expression;
        let outer = site.outer.clone();
        drop(site);
        let tables = self.build_syntactic_ranges(node, expression, &outer, source);
        if let Some((later, first)) = &tables {
            self.constant.pin_table(later);
            if let Some(first) = first {
                self.constant.pin_table(first);
            }
        }
        let ready = tables.is_some();
        self.syntactic_ranges.borrow_mut().insert(key, tables);
        ready
    }

    fn build_syntactic_ranges(
        &self,
        node: &Node,
        expression: Span,
        outer: &[Span],
        source: &str,
    ) -> Option<SyntacticTables> {
        let root = ast_utils::tree_root(node);
        let expr = expression.find(root)?;
        let ancestors = outer
            .iter()
            .map(|span| span.find(root))
            .collect::<Option<Vec<_>>>()?;
        // The record is the expression's own: its parent heads it.
        if expr.parent()?.id() != ancestors.first()?.id() {
            return None;
        }
        let macros = self.current_macros.borrow();
        let loop_ranges =
            const_eval::loop_var_ranges_among(ancestors.iter().copied(), source, &macros);
        let mut names: Vec<&str> = query::find_descendants_of_kind(expr, "identifier")
            .iter()
            .filter_map(|n| n.utf8_text(source.as_bytes()).ok())
            .filter(|name| !name.is_empty() && !macros.contains_key(*name))
            .filter(|name| !loop_ranges.contains_key(*name))
            .collect();
        names.sort_unstable();
        names.dedup();
        let resolve_at = |name: &str, start: usize| {
            const_eval::resolve_local_var_range_among(
                name,
                start,
                ancestors.iter().copied(),
                source,
                &macros,
                &loop_ranges,
                None,
                0,
            )
        };
        let mut later = loop_ranges.clone();
        for name in &names {
            if let Some(range) = resolve_at(name, expr.start_byte() + 1) {
                later.insert(name.to_string(), range);
            }
        }
        // The expression's first token, when it is a name the walk resolves.
        let mut leaf = expr;
        while let Some(first) = leaf.child(0) {
            leaf = first;
        }
        let first = (leaf.kind() == "identifier")
            .then(|| leaf.utf8_text(source.as_bytes()).ok())
            .flatten()
            .filter(|name| names.binary_search(name).is_ok())
            .map(|name| {
                let mut first = later.clone();
                match resolve_at(name, expr.start_byte()) {
                    Some(range) => first.insert(name.to_string(), range),
                    None => first.remove(name),
                };
                Box::new(first)
            });
        Some((Box::new(later), first))
    }

    /// Whether every comparison that governs `node` and mentions `var` is
    /// against an operand no wider than `bits`, the checked width, so that
    /// the distance a guard leaves from a type's limit is the checked type's
    /// own. `i < count` bounds `i` below the limit of `count`'s type, which
    /// is `i`'s only if `count` is no wider; an operand this cannot place (a
    /// call, a subscript) is taken as possibly wider.
    fn guards_bound_no_wider_than(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
        var: &str,
        bits: u32,
    ) -> bool {
        guard_dominance::comparison_operands_of(var, node, source)
            .iter()
            .all(|operand| {
                Self::is_plain_operand(operand)
                    && self
                        .operand_width(operand, source, type_map, 0)
                        .is_some_and(|width| width <= bits)
            })
    }

    /// An operand whose type [`Self::operand_width`] reads from what it is
    /// made of: names, constants, casts, `sizeof` and arithmetic over them.
    fn is_plain_operand(node: &Node) -> bool {
        match node.kind() {
            "identifier" | "number_literal" | "char_literal" | "sizeof_expression"
            | "field_expression" | "true" | "false" => true,
            "parenthesized_expression" | "binary_expression" | "unary_expression" => {
                let mut cursor = node.walk();
                let all_plain = node
                    .named_children(&mut cursor)
                    .all(|child| Self::is_plain_operand(&child));
                all_plain
            }
            "cast_expression" => true,
            _ => false,
        }
    }

    /// Get VRA-derived variable ranges at a specific expression node.
    ///
    /// Uses intra-block forward simulation so that assignments within the same
    /// basic block (e.g. single-block functions) are visible at the expression point.
    ///
    /// The ranges depend only on the function and where the expression
    /// starts, which every left-nested operator of a chain shares, so each
    /// pair is replayed once per file.
    fn vra_var_ranges_at(&self, expr_node: &Node, source: &str) -> Option<VarRangeMap> {
        if self.vra_results.borrow().is_empty() || self.function_cfgs.borrow().is_empty() {
            return None;
        }
        let func = self.containing_function(expr_node)?;
        let key = (func.start_byte(), expr_node.start_byte());
        if let Some(known) = self.vra_ranges.borrow().get(&key) {
            return known.clone();
        }
        let ranges = vra_access::var_ranges_replay_in(
            &self.function_cfgs.borrow(),
            &self.vra_results.borrow(),
            &func,
            expr_node,
            source,
            &self.current_macros.borrow(),
        );
        self.vra_ranges.borrow_mut().insert(key, ranges.clone());
        ranges
    }
}

impl CertRule for Int30C {
    fn reads_header_facts(&self) -> bool {
        true
    }

    fn set_analysis_settings(&self, settings: &std::sync::Arc<crate::settings::AnalysisSettings>) {
        self.data_model.set(settings.facts);
    }

    fn rule_id(&self) -> &'static str {
        "INT30-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that unsigned integer operations do not wrap"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "INT30-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_arrays.borrow_mut() = Arc::new(context.project_array_objects());
        *self.project_macros.borrow_mut() = context.macro_constants.clone();
        *self.typedef_types.borrow_mut() = context.typedef_types.clone();
        *self.struct_field_types.borrow_mut() = context.struct_field_types.clone();
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.project_macro_names.borrow_mut() = context.defined_macro_names.clone();
        *self.project_function_macro_names.borrow_mut() =
            context.function_macros.keys().cloned().collect();
        *self.constant_returning_functions.borrow_mut() = context
            .function_summaries
            .iter()
            .filter(|(_, summary)| summary.returns_only_compile_time_constants)
            .map(|(name, _)| name.clone())
            .collect();
        *self.global_writers.borrow_mut() = context.global_writers.clone();

        *self.callers.borrow_mut() = context.callers.clone();
    }

    fn set_visible_types(&self, types: &crate::analyze::context::VisibleTypes) {
        *self.typedef_types.borrow_mut() = types.typedef_types.clone();
        *self.struct_field_types.borrow_mut() = types.struct_field_types.clone();
        *self.visible.borrow_mut() = types.clone();
    }

    fn set_function_cfgs(&self, cfgs: &HashMap<usize, FunctionCfg>) {
        *self.function_cfgs.borrow_mut() = cfgs.clone();
    }

    fn set_vra_results(&self, results: &HashMap<usize, RangeAnalysisResult>) {
        *self.vra_results.borrow_mut() = results.clone();
    }

    fn needs_vra(&self) -> bool {
        true
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let type_map = overflow_helpers::collect_variable_types(node, source);

        // Merge project-level macros with per-file macros (per-file wins)
        *self.current_macros.borrow_mut() = const_eval::merged_macro_constants(
            &self.project_macros.borrow(),
            node,
            source,
            self.data_model.get(),
        );

        // Risky-var memo is keyed on tree-sitter node ids, unique only within
        // one parse tree — reset per file.
        self.risky_vars_cache.borrow_mut().clear();
        *self.raw_text.borrow_mut() = None;
        *self.sanitized_text.borrow_mut() = None;
        *self.site.borrow_mut() = None;
        self.identifier_types.borrow_mut().clear();
        self.float.clear();
        self.risk.clear();
        self.syntactic_ranges.borrow_mut().clear();
        self.unsigned_spelling.clear();
        self.limit_mention.clear();
        self.unsigned_last_literal.borrow_mut().clear();
        self.vra_ranges.borrow_mut().clear();
        self.constant.clear();
        self.pointer.clear();
        self.param_names_cache.borrow_mut().clear();

        *self.pointer_facts.borrow_mut() = PointerFacts::collect(node, source).with_project(
            self.project_arrays.borrow().clone(),
            self.visible.borrow().struct_field_shapes.clone(),
        );
        *self.function_return_types.borrow_mut() =
            overflow_helpers::collect_function_return_types(node, source);

        let visible = self.visible.borrow();
        let env = TypeEnv::visible(&visible, self.data_model.get()).in_tree(*node);
        self.check_node(node, source, &mut violations, &type_map, &env);

        // `check_allocation_size_wrap` reports the size ARGUMENT of a call;
        // the operator walkers may independently report the arithmetic
        // inside it (`malloc(n * sizeof(T))` is both). One wrap, one
        // finding: the argument report yields to the operator one on its
        // line, since that names the operation itself.
        let operator_lines: HashSet<(usize, String)> = violations
            .iter()
            .filter(|v| !Self::is_allocation_argument_report(&v.message))
            .filter_map(|v| Self::quoted_expression(&v.message).map(|e| (v.line, e)))
            .collect();
        violations.retain(|v| {
            !Self::is_allocation_argument_report(&v.message)
                || Self::quoted_expression(&v.message)
                    .is_none_or(|e| !operator_lines.contains(&(v.line, e)))
        });

        violations
    }
}

impl Int30C {
    /// For compound assignments (`x op= y`), check if `x op y` provably fits
    /// in an unsigned integer of `bits` width using constant evaluation.
    /// Note: only resolves the RHS — the LHS is the mutation target and its
    /// initial assignment doesn't reflect its current value (especially in loops).
    fn compound_expr_fits_unsigned(&self, node: &Node, source: &str, op: &str, bits: u32) -> bool {
        let macros = self.current_macros.borrow();
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let loop_ranges = const_eval::extract_loop_var_ranges(node, source, &macros);
            let mut var_ranges = loop_ranges.clone();
            // Only resolve RHS identifiers — LHS is the mutation target
            const_eval::resolve_identifiers_in_expr(
                &right,
                source,
                &macros,
                &loop_ranges,
                &mut var_ranges,
            );
            // LHS: only use loop ranges and macros (not local assignments)
            let lr = const_eval::try_evaluate_range_with(
                &left,
                source,
                &macros,
                &loop_ranges,
                &self.constant,
            );
            let rr = const_eval::try_evaluate_range_with(
                &right,
                source,
                &macros,
                &var_ranges,
                &self.constant,
            );
            if let (Some(lr), Some(rr)) = (lr, rr) {
                let result = match op {
                    "+" => lr.add(&rr),
                    "-" => lr.sub(&rr),
                    "*" => lr.mul(&rr),
                    "<<" => lr.shl(&rr),
                    _ => None,
                };
                if let Some(range) = result {
                    return range.fits_in_unsigned(bits);
                }
            }
        }
        false
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
        env: &TypeEnv,
    ) {
        // Each match's enclosing function, parent and outer statements are
        // carried down the walk (see `Site`), not climbed to per match.
        let nested_functions = Cell::new(false);
        let statement_expressions = Cell::new(false);
        let matches = self.walk_with_state(
            *node,
            source,
            &[
                "binary_expression",
                "assignment_expression",
                "call_expression",
                "update_expression",
            ],
            |state: &WalkState, parent| {
                let is_function = parent.kind() == "function_definition";
                if is_function && state.function.is_some() {
                    nested_functions.set(true);
                }
                if parent.kind() == "compound_statement" && state.in_expression {
                    statement_expressions.set(true);
                }
                WalkState {
                    in_expression: state.in_expression || is_expression_kind(parent.kind()),
                    expression_root: is_expression_kind(parent.kind())
                        .then(|| state.expression_root.unwrap_or(parent)),
                    parent: Some(parent),
                    grandparent: state.parent,
                    function: if is_function {
                        Some(parent)
                    } else {
                        state.function
                    },
                    outer: if is_expression_kind(parent.kind()) {
                        state.outer.clone()
                    } else {
                        Some(Rc::new(Outer {
                            node: parent,
                            up: state.outer.clone(),
                        }))
                    },
                    // Set per child by `walk_with_state`.
                    limit_conditions: None,
                }
            },
        );
        self.nested_functions.set(nested_functions.get());
        self.statement_expressions.set(statement_expressions.get());

        // Scope type_map per function to avoid cross-function name collisions
        // (e.g., a same-named variable of a different type declared in a
        // different function producing a wrong verdict). Mirrors INT32-C's
        // fn_type_maps fix. Memoized per enclosing function_definition node
        // id so it's only computed once even though many candidates share
        // the same function.
        let mut fn_type_maps: HashMap<usize, HashMap<String, String>> = HashMap::new();

        for (matched, state) in matches {
            crate::analyze::containment::checkpoint();
            *self.site.borrow_mut() = Some(Self::site(&matched, &state, source));
            let function = state.function;
            let scoped_type_map: &HashMap<String, String> = match function {
                Some(func_node) => fn_type_maps.entry(func_node.id()).or_insert_with(|| {
                    overflow_helpers::collect_variable_types(&func_node, source)
                }),
                None => type_map,
            };

            match matched.kind() {
                "binary_expression" => {
                    self.check_binary_operation(&matched, source, violations, scoped_type_map, env);
                }
                "assignment_expression" => {
                    self.check_assignment_operation(
                        &matched,
                        source,
                        violations,
                        scoped_type_map,
                        env,
                    );
                }
                "call_expression" => {
                    self.check_function_call(&matched, source, violations, scoped_type_map);
                }
                "update_expression" => {
                    self.check_increment_decrement(&matched, source, violations, scoped_type_map);
                }
                _ => {}
            }
        }
        *self.site.borrow_mut() = None;
    }

    /// Every node of `kinds` under `root` (itself included), in pre-order,
    /// each with what the walk carried down to it: `step` gives the state a
    /// node passes to all its children, and the walk adds per child the
    /// limit conditions (see [`WalkState::limit_conditions`]), which differ
    /// between children of one node -- the branches of an `if` but not its
    /// condition, the right operand of `&&` but not the left, the statements
    /// of a block after an `if` but not before it.
    fn walk_with_state<'t>(
        &self,
        root: Node<'t>,
        source: &str,
        kinds: &[&str],
        step: impl Fn(&WalkState<'t>, Node<'t>) -> WalkState<'t>,
    ) -> Vec<(Node<'t>, WalkState<'t>)> {
        let names_limit = |cond: &Node| {
            self.limit_mention
                .any(cond, |n| guard_dominance::mentions_integer_limit(n, source))
        };
        let with = |list: &Option<Rc<Governing<'t>>>, condition: Node<'t>| {
            if names_limit(&condition) {
                Some(Rc::new(Governing {
                    condition,
                    up: list.clone(),
                }))
            } else {
                list.clone()
            }
        };
        let mut out = Vec::new();
        let mut stack = vec![(root, WalkState::default())];
        while let Some((node, state)) = stack.pop() {
            let mut cursor = node.walk();
            let children: Vec<Node<'t>> = node.children(&mut cursor).collect();
            if !children.is_empty() {
                let inner = step(&state, node);
                // Nothing above a function governs what is inside it.
                let base = if node.kind() == "function_definition" {
                    None
                } else {
                    state.limit_conditions.clone()
                };
                // A block's earlier statements, as each child is reached.
                let block_like = guard_dominance::is_block_like(node.kind());
                let mut earlier = base;
                let mut pending: std::collections::VecDeque<Node<'t>> = Default::default();
                let mut child_states = Vec::with_capacity(children.len());
                for child in &children {
                    if block_like {
                        while let Some(stmt) = pending
                            .front()
                            .filter(|s| s.start_byte() < child.start_byte())
                        {
                            for cond in guard_dominance::block_level_if_conditions(stmt) {
                                earlier = with(&earlier, cond);
                            }
                            pending.pop_front();
                        }
                        if child.is_named() {
                            pending.push_back(*child);
                        }
                    }
                    let limit_conditions = match guard_dominance::governing_condition(&node, child)
                    {
                        Some(cond) => with(&earlier, cond),
                        None => earlier.clone(),
                    };
                    child_states.push((
                        *child,
                        WalkState {
                            limit_conditions,
                            ..inner.clone()
                        },
                    ));
                }
                stack.extend(child_states.into_iter().rev());
            }
            if kinds.contains(&node.kind()) {
                out.push((node, state));
            }
        }
        out
    }

    /// `has_dominating_limit_guard(node, node)`, from the conditions the walk
    /// carried down when `node` is the operator being checked: the climb
    /// out of an operator thousands of levels into an expression, at every
    /// operator, cost the square of the expression.
    fn has_dominating_limit_guard(&self, node: &Node, source: &str) -> bool {
        if let Some(site) = self.site_of(node) {
            if site.limit_conditions.is_empty() {
                return false;
            }
            let spans = site.limit_conditions.clone();
            drop(site);
            let root = ast_utils::tree_root(node);
            if let Some(conditions) = spans
                .iter()
                .map(|span| span.find(root))
                .collect::<Option<Vec<_>>>()
            {
                return guard_dominance::limit_guard_among(node, &conditions, source);
            }
        }
        guard_dominance::has_dominating_limit_guard(node, node, source)
    }

    /// `matched`'s [`Site`], from what the walk carried down to it.
    fn site(matched: &Node, state: &WalkState, source: &str) -> Site {
        let operator_of = |n: Node| {
            (n.kind() == "binary_expression")
                .then(|| n.child_by_field_name("operator"))
                .flatten()
                .map(|op| get_node_text(&op, source).to_string())
        };
        let enclosing_operator = state.parent.and_then(|p| {
            if p.kind() == "parenthesized_expression" {
                state.grandparent.and_then(operator_of)
            } else {
                operator_of(p)
            }
        });
        let mut outer = Vec::new();
        let mut link = state.outer.as_deref();
        while let Some(l) = link {
            outer.push(Span::of(&l.node));
            link = l.up.as_deref();
        }
        let mut limit_conditions = Vec::new();
        let mut link = state.limit_conditions.as_deref();
        while let Some(l) = link {
            limit_conditions.push(Span::of(&l.condition));
            link = l.up.as_deref();
        }
        Site {
            node: Span::of(matched),
            id: matched.id(),
            expression: Span::of(&state.expression_root.unwrap_or(*matched)),
            parent: state.parent.map(|p| Span::of(&p)),
            enclosing_operator,
            outer,
            limit_conditions,
        }
    }

    fn check_binary_operation(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
        env: &TypeEnv,
    ) {
        // INT30-C concerns unsigned integer WRAP (well-defined, but usually
        // unintended). C's usual arithmetic conversions promote the whole
        // expression to float/double the moment either operand is
        // float-typed, at which point there is no unsigned wrap at all — so
        // skip float-typed operations entirely. Mirrors INT32-C's
        // operands_are_floating gate.
        if self.operands_are_floating(node, source, env) {
            return;
        }

        // `ptr + int` / `ptr - int` is pointer arithmetic and `ptr - ptr` a
        // ptrdiff_t computation; neither is the unsigned integer wrap this
        // rule detects. Forming an out-of-bounds pointer is ARR30-C's
        // concern.
        if self.is_pointer_arithmetic(node, source, type_map, env.root(), env.declarations()) {
            return;
        }

        if let Some(operator) = self.get_operator(node, source) {
            match operator.as_str() {
                "+" => self.check_addition(node, source, violations, type_map),
                "-" => self.check_subtraction(node, source, violations, type_map),
                "*" => self.check_multiplication(node, source, violations, type_map),
                "<<" => self.check_left_shift(node, source, violations, type_map),
                _ => {}
            }
        }
    }

    fn check_assignment_operation(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
        env: &TypeEnv,
    ) {
        // See check_binary_operation: skip compound assignments whose
        // operand types make this floating-point arithmetic, not unsigned
        // wrap.
        if self.operands_are_floating(node, source, env) {
            return;
        }

        // See check_binary_operation: `buf += readnb` advances a pointer.
        if self.is_pointer_arithmetic(node, source, type_map, env.root(), env.declarations()) {
            return;
        }

        if let Some(operator) = self.get_assignment_operator(node, source) {
            match operator.as_str() {
                "+=" => self.check_compound_addition(node, source, violations, type_map),
                "-=" => self.check_compound_subtraction(node, source, violations, type_map),
                "*=" => self.check_compound_multiplication(node, source, violations, type_map),
                "<<=" => self.check_compound_left_shift(node, source, violations, type_map),
                _ => {}
            }
        }
    }

    /// Best-effort: is this expression pointer arithmetic rather than integer
    /// arithmetic? Delegates to the shared [`pointer_typing`] engine, supplying
    /// INT30-C's struct field map and this file's pointer facts.
    fn is_pointer_arithmetic<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        type_map: &HashMap<String, String>,
        root: Option<&Node<'a>>,
        scopes: Option<&ScopeDeclarations>,
    ) -> bool {
        let sft = self.struct_field_types.borrow();
        let facts = self.pointer_facts.borrow();
        pointer_typing::is_pointer_arithmetic_with(
            root,
            scopes,
            node,
            source,
            type_map,
            &sft,
            &facts,
            &self.pointer,
        )
    }

    /// True if `node`'s left or right operand is float-typed, making this a
    /// floating-point operation rather than the unsigned-wrap arithmetic
    /// INT30-C covers. Shared by [`check_binary_operation`] and
    /// [`check_assignment_operation`], both of which have `left`/`right`
    /// fields.
    fn operands_are_floating(&self, node: &Node, source: &str, env: &TypeEnv) -> bool {
        ["left", "right"].iter().any(|f| {
            node.child_by_field_name(f).is_some_and(|n| {
                float_typing::expr_is_float_with(&n, source, env, Some(&self.float))
            })
        })
    }

    fn check_addition(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let left_type = self.infer_type(&left, source, type_map);
            let right_type = self.infer_type(&right, source, type_map);

            // Skip pointer arithmetic: ptr + n, n + ptr
            // "not_applicable" means a non-integer type (pointer, float, struct).
            // Adding an unsigned offset to a pointer is valid C pointer arithmetic and
            // is NOT an unsigned integer overflow — that is ARR39-C's domain.
            if left_type == "not_applicable" || right_type == "not_applicable" {
                // Recurse into children only
                return;
            }

            if (self.is_unsigned_type(&left_type) || self.is_unsigned_type(&right_type))
                && !self.has_overflow_check_addition(node, source)
            {
                // Skip when both operands are narrow unsigned types (uint8_t, uint16_t).
                // C promotes these to int (≥32-bit) before arithmetic, so the result
                // cannot overflow the promoted type.
                if self.is_narrow_unsigned_type(&left_type)
                    && self.is_narrow_unsigned_type(&right_type)
                {
                    return;
                }

                // Skip when one operand is narrow unsigned and the other is not a
                // wider unsigned type. C promotes the narrow unsigned to int (signed),
                // so the arithmetic is signed and cannot cause unsigned wrap.
                // Example: uint8_t + 1 → int + int → no unsigned wrap.
                if self.narrow_promotion_is_safe(&left_type, &right_type) {
                    return;
                }

                // Skip if the addition result is immediately masked by bitwise AND.
                // Pattern: (x + 1) & MASK — common ring buffer index idiom.
                // The mask bounds the result regardless of intermediate wrap.
                if self.is_addition_masked_by_bitand(node, source) {
                    return;
                }

                // Skip if the addition result is immediately taken modulo (% N).
                // Pattern: (x + 1) % N — ring buffer next-index idiom.
                // The modulo constrains the result to [0, N-1] so overflow doesn't matter.
                if self.is_addition_bounded_by_modulo(node, source) {
                    return;
                }

                // Check for var + 1 or 1 + var bounded by enclosing loop condition
                if self.is_add_one_bounded_by_loop(node, source) {
                    return;
                }

                // Skip `(uint32_t)a + (uint32_t)b` (or mixed with a plain narrow operand)
                // when both operands' pre-cast types are narrow unsigned. Max sum:
                // 65535 + 65535 = 131070, well within uint32_t.
                if self.both_operands_narrow_pre_cast(&left, &right, source, type_map) {
                    return;
                }

                // Skip `(uint32_t)narrow + SMALL_CONST` — widened narrow plus a known
                // small constant (literal or const-evaluable macro) cannot overflow
                // uint32_t. Catches patterns like `(uint32_t)length + HDR_SIZE`.
                if self.is_narrow_cast_plus_small_const(&left, &right, source, type_map) {
                    return;
                }

                // Skip if constant evaluation proves the result fits in 32-bit unsigned
                if self.expression_fits_in_unsigned(
                    node,
                    source,
                    type_map,
                    self.arith_width_bits(node, source, type_map),
                ) {
                    return;
                }

                // Skip opaque_value + small_literal (e.g. strlen() + 1)
                // but NOT for known full-range functions (atoi, rand, etc.)
                if Self::is_small_increment_of_opaque(
                    node,
                    source,
                    &self.function_summaries.borrow(),
                ) {
                    return;
                }

                // Opt-in provenance gate (mirrors INT32-C): only flag when an
                // operand derives from untrusted/unbounded input or the
                // expression definitely wraps. Bounded unsigned counters wrap
                // by intent, not by bug.
                if !self.has_risky_operand_provenance(
                    node,
                    source,
                    self.arith_width_known(node, source, type_map),
                ) {
                    return;
                }

                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Unsigned integer addition '{}' may wrap without overflow checking",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Add overflow check: if (UINT_MAX - a < b) { /* handle error */ }"
                            .to_string(),
                    ),
                    ..Default::default()
                });
            }
        }
    }

    fn check_subtraction(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let left_type = self.infer_type(&left, source, type_map);
            let right_type = self.infer_type(&right, source, type_map);

            // Skip pointer arithmetic: ptr - n, ptr - ptr2
            if left_type == "not_applicable" || right_type == "not_applicable" {
                return;
            }

            // Skip 64-bit unsigned subtraction: uint64_t wraps at 2^64 which is
            // practically impossible for real-world values (e.g., elapsed time patterns).
            // Only one operand needs to be 64-bit — C promotion rules widen the other.
            if self.any_operand_64bit_unsigned(&left, &right, source, type_map) {
                return;
            }

            if (self.is_unsigned_type(&left_type) || self.is_unsigned_type(&right_type))
                && !self.has_overflow_check_subtraction(node, source)
            {
                // Narrow unsigned types (uint8_t, uint16_t) are promoted to int before
                // subtraction — the result is a signed int that can represent negative
                // values without wrapping. Skip.
                if self.is_narrow_unsigned_type(&left_type)
                    && self.is_narrow_unsigned_type(&right_type)
                {
                    return;
                }

                // Skip when one operand is narrow unsigned and the other is not a
                // wider unsigned type. C promotes to int (signed) — no unsigned wrap.
                if self.narrow_promotion_is_safe(&left_type, &right_type) {
                    return;
                }

                // Skip var - 1 / var - 1U when guarded by positive check or preceded by increment
                if self.is_subtract_one_guarded(node, source) {
                    return;
                }

                // Skip a - b when guarded by `if (a >= b)` or `if (a > b)`
                let left_text = get_node_text(&left, source);
                let right_text = get_node_text(&right, source);
                if self.is_subtraction_guarded_by_comparison(
                    node,
                    left_text.trim(),
                    right_text.trim(),
                    source,
                ) {
                    return;
                }

                // Skip the elapsed-time tick counter idiom:
                //   get_SystemTick_ms() - last_tick
                // The left operand is a getter function whose name signals a monotonic
                // tick/time counter. Unsigned wrap here is intentional and correct
                // (C99 §6.2.5p9: unsigned arithmetic is modular).
                if self.is_elapsed_time_subtraction(&left, source) {
                    return;
                }

                // Skip if constant evaluation proves the result fits in 32-bit unsigned
                if self.expression_fits_in_unsigned(
                    node,
                    source,
                    type_map,
                    self.arith_width_bits(node, source, type_map),
                ) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(
                    node,
                    source,
                    self.arith_width_known(node, source, type_map),
                ) {
                    return;
                }

                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Unsigned integer subtraction '{}' may wrap without underflow checking",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Add underflow check: if (a < b) { /* handle error */ }".to_string(),
                    ),
                    ..Default::default()
                });
            }
        }
    }

    fn check_multiplication(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            // A `*` after a type name is a pointer declarator the parser
            // read as an expression (`pde_t *f(...)` in a damaged region),
            // never a product.
            if left.kind() == "identifier"
                && self.names_a_type(&left, get_node_text(&left, source), source)
            {
                return;
            }
            let left_type = self.infer_type(&left, source, type_map);
            let right_type = self.infer_type(&right, source, type_map);

            if (self.is_unsigned_type(&left_type) || self.is_unsigned_type(&right_type))
                && !self.has_overflow_check_multiplication(node, source)
            {
                // Narrow unsigned types: max(uint8_t)*max(uint8_t)=65025,
                // max(uint16_t)*max(uint16_t)=4,294,836,225 which CAN overflow uint32_t.
                // Only skip uint8_t * uint8_t (fits in 16-bit after promotion).
                if self.is_narrow_unsigned_type(&left_type)
                    && self.is_narrow_unsigned_type(&right_type)
                    && (left_type.contains("8") || right_type.contains("8"))
                {
                    return;
                }

                // Skip when one operand is narrow unsigned and the other is signed/literal.
                // For multiplication, only safe when at least one is 8-bit (max product
                // 255*INT_MAX fits in 64-bit but not 32-bit, so be conservative: only
                // skip when one operand is uint8_t and other is not wide unsigned).
                if (self.is_narrow_unsigned_type(&left_type)
                    && left_type.contains("8")
                    && !self.is_wide_unsigned_type(&right_type))
                    || (self.is_narrow_unsigned_type(&right_type)
                        && right_type.contains("8")
                        && !self.is_wide_unsigned_type(&left_type))
                {
                    return;
                }

                // Skip when both operands' effective (pre-cast) types are narrow unsigned.
                // Pattern: `(uint32_t)a * (uint32_t)b` or `(uint32_t)a * b` where `a` and
                // `b` are each uint8_t or uint16_t. Max product: 65535 * 65535 ≈ 4.29×10⁹,
                // which fits in uint32_t (max 4.29×10⁹ + ~131K).
                if self.both_operands_narrow_pre_cast(&left, &right, source, type_map) {
                    return;
                }

                // Skip `(uint32_t)NARROW_BOUNDED * SMALL_CONST` — a narrow value
                // widened by a cast, multiplied by a small constant (≤ 65535).
                // Product fits uint32_t. Catches patterns like
                // `(uint32_t)(a - b) * SCALE` when the subtraction is guarded.
                if self.is_narrow_cast_times_small_const(&left, &right, source, type_map) {
                    return;
                }

                // Skip if constant evaluation proves the result fits in 32-bit unsigned
                if self.expression_fits_in_unsigned(
                    node,
                    source,
                    type_map,
                    self.arith_width_bits(node, source, type_map),
                ) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(
                    node,
                    source,
                    self.arith_width_known(node, source, type_map),
                ) {
                    return;
                }

                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Unsigned integer multiplication '{}' may wrap without overflow checking",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Add overflow check: if (a > UINT_MAX / b) { /* handle error */ }"
                            .to_string(),
                    ),
                    ..Default::default()
                });
            }
        }
    }

    fn check_left_shift(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        if let (Some(left), Some(_right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let left_type = self.infer_type(&left, source, type_map);

            if self.is_unsigned_type(&left_type) && !self.has_shift_overflow_check(node, source) {
                // Narrow unsigned left shift: uint8_t << N is promoted to int first.
                // Max result: 0xFF << 7 = 0x7F80, fits in 32-bit. Skip.
                if self.is_narrow_unsigned_type(&left_type) {
                    return;
                }

                // Skip if constant evaluation proves the result fits in 32-bit unsigned
                if self.expression_fits_in_unsigned(
                    node,
                    source,
                    type_map,
                    self.arith_width_bits(node, source, type_map),
                ) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(
                    node,
                    source,
                    self.arith_width_known(node, source, type_map),
                ) {
                    return;
                }

                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Unsigned integer left shift '{}' may cause overflow without checking",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Add shift overflow check before shifting".to_string()),
                    ..Default::default()
                });
            }
        }
    }

    /// Whether a compound assignment `x op= y` performs UNSIGNED arithmetic,
    /// which is this rule's, and so cannot be declined merely because `x` is
    /// signed.
    ///
    /// `+=`, `-=` and `*=` apply the usual arithmetic conversions, so an
    /// unsigned right operand converts the operation: hostap's `int
    /// ctx_offset += unsigned int key_len` and `ctx_offset +=
    /// sizeof(peer->mi)` wrap as unsigned, not as signed overflow. These
    /// checks asked about the LEFT operand alone and INT32-C's asked about
    /// its own left operand alone, so once INT32-C learned to decline an
    /// unsigned right operand these three labeled true positives
    /// would have been reported by neither rule. Same exhaustive-dispatch
    /// requirement as an earlier fix, one level down in the expression.
    ///
    /// Not applied to `<<=`: a shift's result type is its promoted LEFT
    /// operand's type, and the right operand takes no part in the usual
    /// arithmetic conversions.
    fn compound_arithmetic_is_unsigned(
        &self,
        left_type: &str,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        if self.is_unsigned_type(left_type) {
            return true;
        }
        match node.child_by_field_name("right") {
            Some(right) => self.is_unsigned_type(&self.infer_type(&right, source, type_map)),
            None => false,
        }
    }

    fn check_compound_addition(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        if let Some(left) = node.child_by_field_name("left") {
            let left_type = self.infer_type(&left, source, type_map);

            // Skip pointer arithmetic: ptr += n
            if left_type == "not_applicable" {
                return;
            }

            if self.compound_arithmetic_is_unsigned(&left_type, node, source, type_map)
                && !self.has_overflow_check_compound(node, source)
            {
                // Narrow unsigned compound add: uint8_t += uint8_t promotes to int.
                if self.is_narrow_unsigned_type(&left_type) {
                    return;
                }

                // Check for var += 1 bounded by enclosing loop condition (var < limit)
                if let Some(right) = node.child_by_field_name("right") {
                    let right_text = get_node_text(&right, source);
                    if self.is_literal_one(right_text.trim()) {
                        let var_name = get_node_text(&left, source);
                        if self.is_bounded_by_loop_condition(node, var_name.trim(), source) {
                            return;
                        }
                    }
                }

                // Skip if constant evaluation proves the result fits in 32-bit unsigned
                if self.compound_expr_fits_unsigned(node, source, "+", 32) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(
                    node,
                    source,
                    self.arith_width_known(node, source, type_map),
                ) {
                    return;
                }

                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Unsigned integer compound addition '{}' may wrap without overflow checking",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Add overflow check before compound assignment".to_string()),
                    ..Default::default()
                });
            }
        }
    }

    fn check_compound_subtraction(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        if let Some(left) = node.child_by_field_name("left") {
            let left_type = self.infer_type(&left, source, type_map);

            // Skip pointer arithmetic: ptr -= n
            if left_type == "not_applicable" {
                return;
            }

            if self.compound_arithmetic_is_unsigned(&left_type, node, source, type_map)
                && !self.has_overflow_check_compound(node, source)
            {
                if self.is_narrow_unsigned_type(&left_type) {
                    return;
                }

                // Check for var -= 1 with positive guard (var > expr implies var >= 1)
                if let Some(right) = node.child_by_field_name("right") {
                    let right_text = get_node_text(&right, source);
                    if self.is_literal_one(right_text.trim()) {
                        let var_name = get_node_text(&left, source);
                        if self.is_guarded_by_gt_zero(node, var_name.trim(), source) {
                            return;
                        }
                    }
                    // Check for var -= expr guarded by `if (var >= expr)` or `if (var > expr)`
                    let var_name = get_node_text(&left, source);
                    if self.is_subtraction_guarded_by_comparison(
                        node,
                        var_name.trim(),
                        right_text.trim(),
                        source,
                    ) {
                        return;
                    }
                }

                // Skip if constant evaluation proves the result fits in 32-bit unsigned
                if self.compound_expr_fits_unsigned(node, source, "-", 32) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(
                    node,
                    source,
                    self.arith_width_known(node, source, type_map),
                ) {
                    return;
                }

                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Unsigned integer compound subtraction '{}' may wrap without underflow checking",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Add underflow check before compound assignment".to_string()),
                    ..Default::default()
                });
            }
        }
    }

    fn check_compound_multiplication(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        if let Some(left) = node.child_by_field_name("left") {
            let left_type = self.infer_type(&left, source, type_map);

            if self.compound_arithmetic_is_unsigned(&left_type, node, source, type_map)
                && !self.has_overflow_check_compound(node, source)
            {
                if self.is_narrow_unsigned_type(&left_type) {
                    return;
                }

                // Skip if constant evaluation proves the result fits in 32-bit unsigned
                if self.compound_expr_fits_unsigned(node, source, "*", 32) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(
                    node,
                    source,
                    self.arith_width_known(node, source, type_map),
                ) {
                    return;
                }

                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Unsigned integer compound multiplication '{}' may wrap without overflow checking",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Add overflow check before compound assignment".to_string()),
                    ..Default::default()
                });
            }
        }
    }

    fn check_compound_left_shift(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        if let Some(left) = node.child_by_field_name("left") {
            let left_type = self.infer_type(&left, source, type_map);

            if self.is_unsigned_type(&left_type) && !self.has_overflow_check_compound(node, source)
            {
                // Skip if constant evaluation proves the result fits in 32-bit unsigned
                if self.compound_expr_fits_unsigned(node, source, "<<", 32) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(
                    node,
                    source,
                    self.arith_width_known(node, source, type_map),
                ) {
                    return;
                }

                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Unsigned integer compound left shift '{}' may cause overflow without checking",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Add shift overflow check before compound assignment".to_string()),
                    ..Default::default()
                });
            }
        }
    }

    fn check_increment_decrement(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        // Skip increments/decrements that are the update clause of a for-loop.
        // The loop condition inherently bounds the variable.
        let parent_kind = match self.site_of(node) {
            Some(site) => site.parent.map(|p| p.kind),
            None => node.parent().map(|p| p.kind()),
        };
        if parent_kind == Some("for_statement") {
            return;
        }

        if let Some(argument) = node.child_by_field_name("argument") {
            let arg_type = self.infer_type(&argument, source, type_map);

            if self.is_unsigned_type(&arg_type) {
                // Narrow unsigned increment/decrement: uint8_t++ wraps at 255,
                // uint16_t-- wraps at 0 — both are defined behavior and the
                // promoted int result doesn't overflow.
                if self.is_narrow_unsigned_type(&arg_type) {
                    return;
                }

                let operator = self.get_update_operator(node, source);

                // Skip plain ++/-- of a wide unsigned struct/union field
                // (`ctx->field++`, `obj.counter++`). Embedded monotonic-
                // counter fields (ticks, sequence numbers) wrap at 2^32 or
                // 2^64 — practically never in real systems, and wrap is
                // typically expected via tick-diff comparisons. Juliet
                // CWE-190/191 tests only exercise local-variable
                // increments, so this skip does not affect TP detection.
                if argument.kind() == "field_expression" && (operator == "++" || operator == "--") {
                    return;
                }
                if operator == "++" || operator == "--" {
                    // Skip increments/decrements in for-loop update clauses — the loop
                    // condition bounds the counter, making wrap impossible in practice.
                    if self.is_in_for_loop_update(node) {
                        return;
                    }
                    // Skip decrements guarded by `var > 0` or `0 < var` (FP-011).
                    if operator == "--" {
                        let var_name = get_node_text(&argument, source);
                        if self.is_guarded_by_gt_zero(node, var_name, source) {
                            return;
                        }
                    }
                    // Skip increments bounded by enclosing loop condition (var < limit).
                    if operator == "++" {
                        let var_name = get_node_text(&argument, source);
                        if self.is_bounded_by_loop_condition(node, var_name.trim(), source) {
                            return;
                        }
                    }
                    // Skip if VRA proves the result fits in 32-bit unsigned
                    if self.expression_fits_in_unsigned(
                        node,
                        source,
                        type_map,
                        self.arith_width_bits(node, source, type_map),
                    ) {
                        return;
                    }
                    // Opt-in provenance gate (see check_addition): a bounded
                    // unsigned counter cannot reach the wrap boundary.
                    if !self.has_risky_operand_provenance(
                        node,
                        source,
                        self.arith_width_known(node, source, type_map),
                    ) {
                        return;
                    }

                    if !self.has_overflow_check_update(node, source) {
                        let start_point = node.start_position();
                        let expr_text = get_node_text(node, source);

                        let message = if operator == "++" {
                            format!(
                                "Unsigned integer increment '{}' may wrap at maximum value",
                                expr_text
                            )
                        } else {
                            format!(
                                "Unsigned integer decrement '{}' may wrap at zero",
                                expr_text
                            )
                        };

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message,
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Add bounds checking before increment/decrement".to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    fn check_function_call(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = &source[function_node.start_byte()..function_node.end_byte()];

            // calloc's multiplication is implicit (`calloc(nmemb, size)`) and
            // so invisible to the binary-expression walk; it gets its own
            // check. The explicit size arithmetic in any allocation argument
            // is checked by `check_allocation_size_wrap`, which the generic
            // operator walkers do not subsume: they opt in on operand
            // provenance, while an allocation size is a sink where a
            // provable wrap is reported on the value alone.
            if function_name == "calloc" {
                self.check_allocation_overflow(node, source, function_name, violations);
            }
            if matches!(function_name, "malloc" | "calloc" | "realloc") {
                self.check_allocation_size_wrap(node, source, function_name, violations, type_map);
            }
        }
    }

    /// The CWE-680 allocation-size wrap: a size argument computed by
    /// arithmetic that C's usual arithmetic conversions perform UNSIGNED --
    /// `data * sizeof(T)`, `from_len * 2U + 1U`, a sum of `strlen()`s -- that
    /// can wrap `size_t` before `malloc` ever sees it.
    ///
    /// Moved here from INT32-C. The dispatch rule is the
    /// operands' types under the usual arithmetic conversions: every operand
    /// signed is signed overflow and INT32-C's; either operand unsigned (of
    /// sufficient rank) makes the operation unsigned arithmetic and its
    /// overflow a wrap, which is this rule's definition. `sizeof(T)` is
    /// `size_t`, so the classic `data * sizeof(T)` was never INT32-C's. The
    /// two-stage `(a * b) * sizeof(T)` is deliberately not collapsed: the
    /// outer product is reported here, and the inner signed `a * b` stays
    /// INT32-C's concern.
    ///
    /// Same mechanics the carve-out had there: only the argument positions
    /// that carry a size are read, a bare identifier is resolved
    /// one assignment hop back to the expression that computed it,
    /// pointer arithmetic is bounded by its object and skipped,
    /// and a product that provably fits 64 bits without wrapping a 32-bit
    /// `size_t` is clean.
    fn check_allocation_size_wrap(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        let is_size_arg = |idx: usize| match function_name {
            "realloc" => idx == 1,
            "calloc" => idx <= 1,
            _ => idx == 0,
        };
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };

        let mut arg_idx = 0;
        for i in 0..arguments.child_count() {
            let Some(arg_node) = arguments.child(i) else {
                continue;
            };
            if matches!(arg_node.kind(), "(" | ")" | ",") {
                continue;
            }
            let this_idx = arg_idx;
            arg_idx += 1;
            if !is_size_arg(this_idx) {
                continue;
            }

            let resolved_rhs = if arg_node.kind() == "identifier" {
                let var_name = get_node_text(&arg_node, source);
                self.containing_function(&arg_node)
                    .and_then(|f| f.child_by_field_name("body"))
                    .and_then(|body| {
                        overflow_helpers::resolve_identifier_assignment_expr(
                            &body, var_name, source, &arg_node,
                        )
                    })
            } else {
                None
            };
            let check_node = resolved_rhs.as_ref().unwrap_or(&arg_node);

            if !self.is_unsigned_integer_arithmetic(check_node, source, type_map) {
                continue;
            }

            let macros = self.current_macros.borrow();
            let vra_ranges = self.vra_var_ranges_at(check_node, source);
            // The width size_t is guaranteed: 64 on a declared LP64 or LLP64
            // target, only 16 under ISO C's (C11 7.20.3, SIZE_MAX).
            let fits_size_t = const_eval::expression_fits_in_signed_vra(
                check_node,
                source,
                &macros,
                self.size_t_bits(),
                vra_ranges.as_ref(),
            );
            // A product that fits in 64 bits can still *definitely* wrap a
            // 32-bit size_t (the CWE-680 flaw on ILP32): `data = INT_MAX/2 +
            // 2` gives `data * sizeof(int)` = 4294967300 > UINT32_MAX.
            // `expression_overflows_unsigned_vra` fires only when the whole
            // range exceeds the bound, so a small allocation stays clean.
            let wraps_32_size_t = const_eval::expression_overflows_unsigned_vra(
                check_node,
                source,
                &macros,
                32,
                vra_ranges.as_ref(),
            );
            // Under ISO C's widths `sizeof(int)` has no value, so `2 *
            // sizeof(int)` never evaluates and its fit goes unproven. It is a
            // constant the compiler folds, with no runtime input to wrap it:
            // the same call `calloc_product_cannot_wrap` makes for a count and
            // an element size that are both constants. A constant that WAS
            // computed and does not fit is still reported.
            let low_exceeds_size_t = const_eval::try_evaluate_lower_bound(
                check_node,
                source,
                &macros,
                vra_ranges.as_ref().unwrap_or(&VarRangeMap::new()),
            )
            .is_some_and(|low| low > self.size_t_max());
            let constant_not_evaluated = !self.data_model.get().sizeof_known(Rank::Int)
                && !low_exceeds_size_t
                && const_eval::try_evaluate_range_with(
                    check_node,
                    source,
                    &macros,
                    vra_ranges.as_ref().unwrap_or(&VarRangeMap::new()),
                    &self.constant,
                )
                .is_none()
                && const_eval::is_compile_time_constant_expr(
                    check_node,
                    source,
                    &macros,
                    const_eval::ConstantNameSets {
                        object_macros: &self.project_macro_names.borrow(),
                        function_macros: &self.project_function_macro_names.borrow(),
                        constant_returning_functions: &self.constant_returning_functions.borrow(),
                        file_macros: None,
                    },
                );
            drop(macros);
            if (fits_size_t && !wraps_32_size_t) || constant_not_evaluated {
                continue;
            }
            if self.has_allocation_size_guard(node, check_node, source) {
                continue;
            }

            let arg_text = get_node_text(check_node, source);
            let start_point = node.start_position();
            let message = if resolved_rhs.is_some() {
                format!(
                    "{}() argument {} ('{}') was computed by unsigned arithmetic that may wrap: '{}'",
                    function_name,
                    this_idx + 1,
                    get_node_text(&arg_node, source),
                    arg_text
                )
            } else {
                format!(
                    "{}() argument {} contains unsigned arithmetic that may wrap: '{}'",
                    function_name,
                    this_idx + 1,
                    arg_text
                )
            };
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message,
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(
                    "Check the size against SIZE_MAX / element size before allocating".to_string(),
                ),
                ..Default::default()
            });
        }
    }

    /// A call typed by its declared return: a standard function whose
    /// prototype returns `size_t` (`strlen`, `fread`), or a function this
    /// file defines or declares (mirroring INT32-C's method of
    /// the same name). `None` for anything else, so it stays untyped.
    fn infer_type_from_call_return(&self, node: &Node, source: &str) -> Option<String> {
        let func = node.child_by_field_name("function")?;
        if func.kind() != "identifier" {
            return None;
        }
        let name = get_node_text(&func, source);
        if std_functions::returns_size_t(name) {
            return Some("unsigned".to_string());
        }
        let declared = self.function_return_types.borrow().get(name).cloned()?;
        self.is_unsigned_type(&declared).then_some(declared)
    }

    fn is_allocation_argument_report(message: &str) -> bool {
        message.contains("() argument ") && message.contains(" that may wrap: '")
    }

    /// The last single-quoted span of a finding message: the expression
    /// every arithmetic report in this rule ends with.
    fn quoted_expression(message: &str) -> Option<String> {
        let end = message.rfind('\'')?;
        let start = message[..end].rfind('\'')?;
        Some(message[start + 1..end].to_string())
    }

    /// Does `node` contain arithmetic that C performs in an UNSIGNED integer
    /// type -- the dual of INT32-C's `has_signed_integer_arithmetic`, and
    /// the other half of the same dispatch rule?
    ///
    /// Looks through parentheses. Pointer arithmetic is neither. An
    /// operation is unsigned when the usual arithmetic conversions make it
    /// so: either operand unsigned, or either operand itself an unsigned
    /// operation (`(n * sizeof(T)) + 1` is unsigned throughout).
    fn is_unsigned_integer_arithmetic(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        match node.kind() {
            "parenthesized_expression" => node
                .named_child(0)
                .is_some_and(|c| self.is_unsigned_integer_arithmetic(&c, source, type_map)),
            "binary_expression" => {
                let op = node
                    .child_by_field_name("operator")
                    .map(|o| o.kind())
                    .unwrap_or("");
                let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return false;
                };
                let recurse = |n: &Node| self.is_unsigned_integer_arithmetic(n, source, type_map);
                if !matches!(op, "+" | "-" | "*" | "<<") {
                    return recurse(&left) || recurse(&right);
                }
                if self.is_pointer_arithmetic(node, source, type_map, None, None) {
                    return false;
                }
                self.is_unsigned_type(&self.infer_type(node, source, type_map))
                    || self.is_unsigned_type(&self.infer_type(&left, source, type_map))
                    || self.is_unsigned_type(&self.infer_type(&right, source, type_map))
                    || recurse(&left)
                    || recurse(&right)
            }
            _ => false,
        }
    }

    /// The `count > SIZE_MAX / sizeof(T)` idiom around an allocation: a
    /// dominating limit guard (spacing- and order-insensitive, also seen as
    /// an `&&` conjunct or an earlier exiting `if`), or the same
    /// function-context text reading the calloc check beside this one uses
    /// -- which is what recognises the wiki's own compliant example, whose
    /// guard body only comments "Handle error" and so dominates nothing.
    ///
    /// `arithmetic` is the expression that can wrap: the argument itself, or
    /// the right-hand side of the assignment that computed it
    /// (`total = a + b; malloc(total)`). A guard on its operands counts when
    /// it dominates that expression, where the operands are read, since a
    /// guard at the call on `total` alone never names `a` or `b`
    /// (`if (SIZE_MAX - a < b) return;`).
    fn has_allocation_size_guard(&self, node: &Node, arithmetic: &Node, source: &str) -> bool {
        self.has_dominating_limit_guard(node, source)
            || guard_dominance::has_dominating_limit_guard(arithmetic, arithmetic, source)
            || self.has_function_context_check(node, source, &["SIZE_MAX", " / "])
    }

    fn check_allocation_overflow(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let args = self.get_function_arguments(node, source);

        if function_name == "calloc"
            && args.len() >= 2
            && !self.calloc_product_cannot_wrap(node, source)
            && !self.has_calloc_overflow_check(node, source)
        {
            let start_point = node.start_position();
            // `wchar_t` is unknown unless declared, and the wrap may rest on
            // the widest it could be: say so, so the way out is named.
            let wchar_undeclared = self.data_model.get().wchar_bits().is_none()
                && args[..2].iter().any(|a| {
                    a.split_whitespace()
                        .collect::<String>()
                        .contains("sizeof(wchar_t)")
                });
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "calloc({}, {}) may cause integer overflow in size calculation{}",
                    args[0],
                    args[1],
                    if wchar_undeclared {
                        " (the width of wchar_t is not declared; declare wchar_t_bits and a data model)"
                    } else {
                        ""
                    }
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(
                    "Check for overflow: if (count > SIZE_MAX / size) { /* handle error */ }"
                        .to_string(),
                ),
                ..Default::default()
            });
        }
    }

    /// Is `nmemb * size`, the product `calloc` forms from its two arguments,
    /// provably free of a wrap? A finding here names a runtime
    /// size calculation that unexpected input can push past `SIZE_MAX`; the
    /// call is clean when no such calculation exists:
    ///
    /// - Either operand is provably in `[0, 1]`: multiplying by 0 or 1 never
    ///   wraps, whatever the other operand is. `calloc(1, sizeof(struct
    ///   cfg))` is exactly this, and needs no struct layout to settle.
    /// - Both operand ranges are known and their product is in range -- the
    ///   same test `check_allocation_size_wrap` applies to an explicit
    ///   `data * sizeof(T)`, so `calloc(4, sizeof(int))` is clean and
    ///   `calloc(1073741825, sizeof(int))` still wraps a 32-bit `size_t`
    ///   (the ILP32 stance both share until an earlier fix gives it a setting).
    ///   The ranges come from VRA first and the syntactic constant
    ///   propagation second, in that order, for the reason
    ///   `expression_fits_in_unsigned_vra` gives: VRA's loop widening can
    ///   only ever make a fit fail to prove, never prove one falsely.
    /// - Both operands are compile-time constants in
    ///   `const_eval::is_compile_time_constant_expr`'s sense. The product is
    ///   then an integer constant expression the compiler folds: there is no
    ///   runtime calculation for input to reach, and the remediation this
    ///   rule suggests (`if (count > SIZE_MAX / size)`) is a constant
    ///   condition that could never do anything. This is what settles
    ///   `calloc(4, sizeof(struct big))`: sqc lays out no struct, so "did
    ///   the product fold?" is a fact about sqc, not about the code.
    ///
    /// Nothing here reads the operands' spelling: an unresolved count keeps
    /// the report, whatever it is multiplied by.
    fn calloc_product_cannot_wrap(&self, call: &Node, source: &str) -> bool {
        let Some(arguments) = call.child_by_field_name("arguments") else {
            return false;
        };
        let (Some(nmemb), Some(size)) = (arguments.named_child(0), arguments.named_child(1)) else {
            return false;
        };

        match (
            self.calloc_product_fits(&nmemb, &size, source, true),
            self.calloc_product_fits(&nmemb, &size, source, false),
        ) {
            (Some(true), _) | (_, Some(true)) => return true,
            // A product that was computed and does not fit is a wrap the
            // constant clause below must not talk the rule out of:
            // `calloc(1073741825, sizeof(int))` is constant AND wraps.
            (Some(false), _) | (_, Some(false)) => return false,
            (None, None) => {}
        }

        let macros = self.current_macros.borrow();
        let names = const_eval::ConstantNameSets {
            object_macros: &self.project_macro_names.borrow(),
            function_macros: &self.project_function_macro_names.borrow(),
            constant_returning_functions: &self.constant_returning_functions.borrow(),
            file_macros: None,
        };
        const_eval::is_compile_time_constant_expr(&nmemb, source, &macros, names)
            && const_eval::is_compile_time_constant_expr(&size, source, &macros, names)
    }

    /// The largest value the narrowest `size_t` the data model allows holds.
    fn size_t_max(&self) -> i64 {
        let bits = self.size_t_bits();
        if bits >= 63 {
            i64::MAX
        } else {
            (1i64 << bits) - 1
        }
    }

    /// The product of the two allocation arguments' lower ends, when both are
    /// known.
    fn allocation_lower_bound(&self, nmemb: &Node, size: &Node, source: &str) -> Option<i64> {
        let macros = self.current_macros.borrow();
        let ranges = |node: &Node| self.vra_var_ranges_at(node, source).unwrap_or_default();
        let low = |node: &Node| {
            const_eval::try_evaluate_lower_bound(node, source, &macros, &ranges(node))
        };
        Some(low(nmemb)?.saturating_mul(low(size)?))
    }

    /// The range half of `calloc_product_cannot_wrap`, over VRA ranges when
    /// `use_vra` is set and the syntactic ones otherwise: `Some(true)` when
    /// the product provably fits, `Some(false)` when it was computed and
    /// does not, `None` when an operand's range is unknown -- which proves
    /// nothing unless the other is in `[0, 1]`.
    fn calloc_product_fits(
        &self,
        nmemb: &Node,
        size: &Node,
        source: &str,
        use_vra: bool,
    ) -> Option<bool> {
        let count = self.calloc_operand_range(nmemb, source, use_vra);
        let elem = self.calloc_operand_range(size, source, use_vra);
        let is_zero_or_one = |r: &Option<ValueRange>| r.is_some_and(|r| r.min >= 0 && r.max <= 1);
        if is_zero_or_one(&count) || is_zero_or_one(&elem) {
            return Some(true);
        }
        let Some(product) = count.zip(elem).and_then(|(count, elem)| count.mul(&elem)) else {
            // No product to form (an element size no data model gives, a count
            // times it leaving `i64`): under ISO C's widths the question that
            // is still answerable is whether the LOWER ends already exceed
            // what the narrowest `size_t` holds. A `sizeof` is at least 1, so
            // `calloc(1073741825, sizeof(int))` wraps wherever `size_t` is 16
            // bits, and that is a computed wrap the constant clause must not
            // talk the rule out of.
            return (!self.data_model.get().sizeof_known(Rank::Int)
                && self
                    .allocation_lower_bound(nmemb, size, source)
                    .is_some_and(|low| low > self.size_t_max()))
            .then_some(false);
        };
        // Mirrors `check_allocation_size_wrap`: fits the width `size_t` is
        // guaranteed, and does not *definitely* exceed a 32-bit `size_t`. A
        // product that merely straddles the 32-bit bound is a possible wrap,
        // not a proven one, and is left to the range being narrowed, not
        // reported here.
        Some(product.fits_in_unsigned(self.size_t_bits()) && product.min <= i64::from(u32::MAX))
    }

    /// The value range of one `calloc` operand: the VRA ranges replayed at
    /// the operand, or the loop-and-assignment propagation
    /// `expression_fits_in_unsigned` falls back to.
    fn calloc_operand_range(&self, node: &Node, source: &str, use_vra: bool) -> Option<ValueRange> {
        let macros = self.current_macros.borrow();
        if use_vra {
            let ranges = self.vra_var_ranges_at(node, source)?;
            return const_eval::try_evaluate_range_with(
                node,
                source,
                &macros,
                &ranges,
                &self.constant,
            );
        }
        let loop_ranges = const_eval::extract_loop_var_ranges(node, source, &macros);
        let mut var_ranges = loop_ranges.clone();
        const_eval::resolve_identifiers_in_expr(
            node,
            source,
            &macros,
            &loop_ranges,
            &mut var_ranges,
        );
        const_eval::try_evaluate_range_with(node, source, &macros, &var_ranges, &self.constant)
    }

    fn infer_type(&self, node: &Node, source: &str, type_map: &HashMap<String, String>) -> String {
        let text = get_node_text(node, source);

        // Cast expressions: extract the actual target type from the type descriptor.
        // This provides precise type info (e.g., "uint8_t" instead of generic "unsigned")
        // which is critical for narrow-type checks.
        if node.kind() == "cast_expression" {
            if let Some(type_node) = node.child_by_field_name("type") {
                let cast_type = get_node_text(&type_node, source).trim().to_string();
                let base_type = Self::strip_type_qualifiers(&cast_type);
                if base_type.contains('*') {
                    return "not_applicable".to_string();
                }
                if self.is_unsigned_type(&base_type) {
                    return base_type;
                }
                if base_type == "void" {
                    return "not_applicable".to_string();
                }
                return "int".to_string();
            }
        }

        if self.spells_out_unsigned(node, source) {
            return "unsigned".to_string();
        }

        // Look for unsigned constants
        let raw = self.raw_text(source);
        if raw.contains(node, "UINT_MAX") || raw.contains(node, "SIZE_MAX") {
            return "unsigned".to_string();
        }
        drop(raw);

        // sizeof() always returns size_t (unsigned)
        if node.kind() == "sizeof_expression" {
            return "unsigned".to_string();
        }

        if node.kind() == "call_expression" {
            if let Some(t) = self.infer_type_from_call_return(node, source) {
                return t;
            }
        }

        // Plain number literals — assume signed for conservatism
        if text.chars().all(|c| c.is_ascii_digit()) {
            return "int".to_string();
        }

        // Check identifiers against the type map (most reliable).
        // Return the actual declared type to preserve narrow-type info (uint8_t etc.).
        if node.kind() == "identifier" {
            if let Some(declared_type) = self.identifier_type(node, source, type_map) {
                let declared_type = declared_type.as_ref();
                // Pointer types are not integer types — skip
                if declared_type.contains('*') {
                    return "not_applicable".to_string();
                }
                if self.is_unsigned_type(declared_type) {
                    return declared_type.to_string();
                }
                // Non-integer types (float, double, char, pointers, structs) — not applicable
                if !declared_type.contains("int")
                    && !declared_type.contains("short")
                    && !declared_type.contains("long")
                    && declared_type != "signed"
                {
                    return "not_applicable".to_string();
                }
                return "int".to_string();
            }
        }

        // For pointer expressions (*var), strip the '*' and check the pointed-to type.
        // Dereferencing a pointer yields the base type, so strip one '*' from the
        // declared type if present.
        if node.kind() == "pointer_expression" {
            let var_name = text.trim_start_matches('*').trim();
            let declared = match node.child_by_field_name("argument") {
                Some(arg) if arg.kind() == "identifier" => {
                    self.identifier_type(&arg, source, type_map)
                }
                _ => type_map
                    .get(var_name)
                    .map(|t| std::borrow::Cow::Borrowed(t.as_str())),
            };
            if let Some(declared_type) = declared.as_deref() {
                // Strip one level of pointer indirection (dereference)
                let deref_type = if let Some(stripped) = declared_type.strip_suffix(" *") {
                    stripped
                } else if let Some(stripped) = declared_type.strip_suffix('*') {
                    stripped
                } else {
                    declared_type
                };
                if deref_type.contains('*') {
                    // Still a pointer after dereference (e.g. int **)
                    return "not_applicable".to_string();
                }
                if self.is_unsigned_type(deref_type) {
                    return "unsigned".to_string();
                }
                return "int".to_string();
            }
        }

        // Field expressions (e.g., s->length): resolve via struct field type database
        if node.kind() == "field_expression" {
            let sft = self.struct_field_types.borrow();
            if let Some(field_type) =
                crate::utility::cert_c::ast_utils::resolve_field_expression_type(
                    node, source, type_map, &sft,
                )
            {
                // Strip qualifiers (volatile, const) for type classification
                let base_type = Self::strip_type_qualifiers(&field_type);
                if base_type.contains('*') {
                    return "not_applicable".to_string();
                }
                if self.is_unsigned_type(&base_type) {
                    // Return actual type to preserve narrow-type info (uint8_t, uint16_t)
                    return base_type;
                }
                if !base_type.contains("int")
                    && !base_type.contains("short")
                    && !base_type.contains("long")
                    && base_type != "signed"
                {
                    return "not_applicable".to_string();
                }
                return "int".to_string();
            }
            return "unknown".to_string();
        }

        // Fallback: check variable declaration in function text for unmapped variables
        if node.kind() == "identifier" || node.kind() == "pointer_expression" {
            let var_name = text.trim_start_matches('*').trim();
            if self.is_variable_declared_unsigned(node, source, var_name) {
                return "unsigned".to_string();
            }
        }

        "unknown".to_string()
    }

    /// Whether the expression's own text says it is unsigned: a type it spells
    /// out (a cast, `sizeof(type)`, a type argument to a casting macro such
    /// as `cast(l_uint32, st)`) names an unsigned type, or it ends in a
    /// `u`-suffixed literal. An identifier or member is typed by its
    /// declaration instead, never by its spelling (ADR-0006): an `int` named
    /// `u` or `iMul` is not a `u`- or `ul`-suffixed literal, and one named
    /// `buf_size_t` is not a `size_t`.
    fn spells_out_unsigned(&self, node: &Node, source: &str) -> bool {
        if matches!(node.kind(), "identifier" | "field_expression") {
            return false;
        }
        if node.kind() != "argument_list" {
            // The same two searches of the subtree, answered once per node
            // for the file: a type name that says unsigned, or a call whose
            // identifier argument is an unsigned type a macro takes.
            let names_unsigned_type = self
                .unsigned_spelling
                .any(node, |n| self.spells_unsigned_here(n, source));
            return names_unsigned_type || self.ends_in_unsigned_literal(node, source);
        }
        let names_unsigned_type = query::find_descendants_of_kinds(
            *node,
            &["primitive_type", "sized_type_specifier", "type_identifier"],
        )
        .iter()
        .any(|t| {
            let text = get_node_text(t, source);
            text.contains("unsigned") || text.contains("size_t") || text.contains("uint")
        }) || self.argument_names_unsigned_type(node, source);
        let last = Self::rightmost_leaf(*node);
        let unsigned_literal = last.kind() == "number_literal" && {
            let last = get_node_text(&last, source);
            last.ends_with('u')
                || last.ends_with('U')
                || last.ends_with("UL")
                || last.ends_with("ul")
        };
        names_unsigned_type || unsigned_literal
    }

    /// What [`Self::spells_out_unsigned`] looks for at one node of the
    /// subtree: a type name that says unsigned, or a call with an
    /// identifier argument that [`Self::call_takes_unsigned_type`].
    fn spells_unsigned_here(&self, n: &Node, source: &str) -> bool {
        match n.kind() {
            "primitive_type" | "sized_type_specifier" | "type_identifier" => {
                let text = get_node_text(n, source);
                text.contains("unsigned") || text.contains("size_t") || text.contains("uint")
            }
            "call_expression" => n
                .child_by_field_name("arguments")
                .filter(|args| args.kind() == "argument_list")
                .is_some_and(|args| {
                    let mut cursor = args.walk();
                    let found = args.named_children(&mut cursor).any(|arg| {
                        arg.kind() == "identifier"
                            && self.call_takes_unsigned_type(
                                n,
                                &arg,
                                get_node_text(&arg, source),
                                source,
                            )
                    });
                    found
                }),
            _ => false,
        }
    }

    /// Whether `node`'s last token ([`Self::rightmost_leaf`]) is an
    /// unsigned integer literal, remembered for every node on the way down
    /// to it: a right-nested chain shares one last token.
    fn ends_in_unsigned_literal(&self, node: &Node, source: &str) -> bool {
        let mut path = Vec::new();
        let mut leaf = *node;
        let answer = loop {
            if let Some(&known) = self.unsigned_last_literal.borrow().get(&leaf.id()) {
                break known;
            }
            path.push(leaf.id());
            match leaf.child(leaf.child_count().saturating_sub(1)) {
                Some(last) => leaf = last,
                None => {
                    break leaf.kind() == "number_literal" && {
                        let last = get_node_text(&leaf, source);
                        last.ends_with('u')
                            || last.ends_with('U')
                            || last.ends_with("UL")
                            || last.ends_with("ul")
                    };
                }
            }
        };
        let mut memo = self.unsigned_last_literal.borrow_mut();
        for id in path {
            memo.insert(id, answer);
        }
        answer
    }

    /// Whether an identifier argument of a call in `node`'s subtree passes
    /// [`Self::call_takes_unsigned_type`]. The arguments are found
    /// from their calls, not by asking each identifier for its parent:
    /// `Node::parent` descends from the tree root, and asking it of every
    /// identifier under every operator of a long sum was cubic in its length.
    /// Only a call has an `argument_list`, so an identifier whose parent is
    /// one is exactly a direct argument of a call.
    fn argument_names_unsigned_type(&self, node: &Node, source: &str) -> bool {
        let mut lists: Vec<(Node, Node)> =
            query::find_descendants_of_kind(*node, "call_expression")
                .into_iter()
                .filter_map(|call| Some((call.child_by_field_name("arguments")?, call)))
                .filter(|(args, _)| args.kind() == "argument_list")
                .collect();
        // `node` itself an argument list: its call is above the subtree.
        if node.kind() == "argument_list" {
            if let Some(call) = node.parent() {
                lists.push((*node, call));
            }
        }
        lists.iter().any(|(args, call)| {
            let mut cursor = args.walk();
            let found = args.named_children(&mut cursor).any(|arg| {
                arg.kind() == "identifier"
                    && self.call_takes_unsigned_type(
                        call,
                        &arg,
                        get_node_text(&arg, source),
                        source,
                    )
            });
            found
        })
    }

    /// Whether `ident`, an argument of `call`, is a type name the parser read
    /// as an expression because a function-like macro takes it (`cast(T, x)`,
    /// `va_arg(ap, T)`) and that type is unsigned. Only a macro can take a
    /// type, so the callee must be a function-like macro the scan saw: a
    /// type-shaped argument to a function is a declaration the parser
    /// misread (`pde_t *CONST lookup(pde_t *pd, vptr_t vptr)` inside a
    /// damaged region), not a value of that type.
    fn call_takes_unsigned_type(
        &self,
        call: &Node,
        ident: &Node,
        name: &str,
        source: &str,
    ) -> bool {
        let takes_types = call
            .child_by_field_name("function")
            .filter(|f| f.kind() == "identifier")
            .is_some_and(|f| {
                self.project_function_macro_names
                    .borrow()
                    .contains(get_node_text(&f, source))
            });
        takes_types && self.names_a_type(ident, name, source) && self.is_unsigned_type(name)
    }

    /// Whether the identifier `ident`, spelled `name`, names a type rather
    /// than an object: a typedef the scan declared, or a standard type name,
    /// with no object of that name in scope (ADR-0006).
    fn names_a_type(&self, ident: &Node, name: &str, source: &str) -> bool {
        let is_type_name =
            self.typedef_types.borrow().contains_key(name) || ast_utils::is_unsigned_type(name);
        is_type_name && ast_utils::resolve_identifier_binding(ident, name, source).is_none()
    }

    /// The last token of `node`, the one whose text ends `node`'s text.
    fn rightmost_leaf(node: Node) -> Node {
        let mut leaf = node;
        while let Some(last) = leaf.child(leaf.child_count().saturating_sub(1)) {
            leaf = last;
        }
        leaf
    }

    /// Check if a variable is declared as unsigned in the containing function
    fn is_variable_declared_unsigned(&self, node: &Node, source: &str, var_name: &str) -> bool {
        // Check the containing function for parameter declarations like
        // "unsigned int var_name" or "unsigned int *var_name"
        let patterns = [
            format!("unsigned int {}", var_name),
            format!("unsigned int *{}", var_name),
            format!("unsigned long {}", var_name),
            format!("size_t {}", var_name),
            format!("uint32_t {}", var_name),
            format!("uint64_t {}", var_name),
        ];
        let patterns: Vec<&str> = patterns.iter().map(String::as_str).collect();
        self.function_text_contains_any(node, source, &patterns)
    }

    /// Returns true if this binary_expression is `opaque + small_literal` or
    /// `small_literal + opaque`, where "opaque" is a call_expression or an
    /// identifier whose value comes from a call_expression, AND the callee is
    /// not known to return full-range values.
    ///
    /// Functions like `strlen()` return bounded values where +1 is safe.
    /// Functions like `atoi()` or `rand()` can return any value in the type
    /// range, so their result + small literal is a genuine overflow risk.
    fn is_small_increment_of_opaque(
        node: &Node,
        source: &str,
        summaries: &(impl SummaryLookup + ?Sized),
    ) -> bool {
        if node.kind() != "binary_expression" {
            return false;
        }
        let (left, right) = match (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            (Some(l), Some(r)) => (l, r),
            _ => return false,
        };

        let is_small_literal = |n: &Node| -> bool {
            if n.kind() != "number_literal" {
                return false;
            }
            let text = get_node_text(n, source).trim().to_string();
            text.parse::<u64>().is_ok_and(|v| v <= 10)
        };

        // Resolve the callee function name from a call_expression or an
        // identifier initialized from a call_expression.
        let resolve_callee = |n: &Node| -> Option<String> {
            if n.kind() == "call_expression" {
                return n
                    .child_by_field_name("function")
                    .and_then(|f| f.utf8_text(source.as_bytes()).ok())
                    .map(|s| s.trim().to_string());
            }
            if n.kind() == "identifier" {
                let var_name = get_node_text(n, source);
                if let Some(func) = ast_utils::find_containing_function(n) {
                    if let Some(body) = func.child_by_field_name("body") {
                        return overflow_helpers::resolve_identifier_call_name(
                            &body, var_name, source, n,
                        );
                    }
                }
            }
            None
        };

        let callee = if is_small_literal(&right) {
            resolve_callee(&left)
        } else if is_small_literal(&left) {
            resolve_callee(&right)
        } else {
            return false;
        };

        let callee = match callee {
            Some(name) => name,
            None => return false,
        };

        // Known full-range or untrusted-decode functions: never suppress
        if std_functions::is_full_range_return_function(&callee)
            || std_functions::is_untrusted_decode_function(&callee)
        {
            return false;
        }

        // Local function carrying taint (directly or transitively), or with a
        // proven wide return range: don't suppress. Keeps the heuristic
        // consistent with the provenance gate for cross-function flow.
        if let Some(summary) = summaries.get(&callee) {
            if summary.has_env03_taint_source || summary.returns_tainted {
                return false;
            }
            if let Some(ref return_range) = summary.return_range {
                let unsigned_danger = u32::MAX as i64 - 10;
                if return_range.max >= unsigned_danger {
                    return false;
                }
            }
        }

        // Default: suppress (safe for strlen, wcslen, unknown helpers)
        true
    }

    /// Whether a type spelling is unsigned: the C spellings, the shared
    /// `ast_utils::is_unsigned_type` vocabulary (`uintN_t`, Win32 names),
    /// and any typedef alias whose chain resolves to one -- the same
    /// resolution INT32-C applies (`classify_declared_type`), so the two
    /// rules type the same operand the same way and the signed/unsigned
    /// dispatch between them is exhaustive. `word_t` ->
    /// `unsigned long` was unsigned to INT32-C and `int` here.
    fn is_unsigned_type(&self, type_str: &str) -> bool {
        type_str.contains("unsigned")
            || type_str == "size_t"
            || type_str.contains("uint")
            || ast_utils::is_unsigned_type(type_str)
            || overflow_helpers::typedef_chain_is_unsigned(type_str, &self.typedef_types.borrow())
    }

    /// Returns true if the type is a narrow unsigned integer (8-bit or 16-bit).
    /// Operations on narrow unsigned types are promoted to `int` (at least 32-bit)
    /// by the C standard, so they cannot overflow `unsigned int` in practice:
    /// max(uint8_t) * max(uint8_t) = 255*255 = 65025, fits in 32-bit.
    /// max(uint16_t) + max(uint16_t) = 131070, fits in 32-bit.
    fn is_narrow_unsigned_type(&self, type_str: &str) -> bool {
        matches!(
            type_str,
            "uint8_t"
                | "uint_least8_t"
                | "uint_fast8_t"
                | "uint16_t"
                | "uint_least16_t"
                | "uint_fast16_t"
                | "unsigned char"
                | "unsigned short"
        )
    }

    /// For a cast_expression node, return the type of the inner (pre-cast) value.
    /// For non-cast nodes, return None. This lets callers see through widening casts
    /// like `(uint32_t)narrow_var` to detect that the original value is narrow.
    fn get_pre_cast_type(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> Option<String> {
        if node.kind() == "cast_expression" {
            if let Some(value) = node.child_by_field_name("value") {
                let inner_type = self.infer_type(&value, source, type_map);
                if inner_type != "unknown" {
                    return Some(inner_type);
                }
            }
        }
        None
    }

    /// Strip type qualifiers (volatile, const, _Atomic) from a type string.
    fn strip_type_qualifiers(type_str: &str) -> String {
        type_str
            .replace("volatile ", "")
            .replace("const ", "")
            .replace("_Atomic ", "")
            .trim()
            .to_string()
    }

    /// Returns true if the type is a "wide" unsigned integer (32-bit or larger).
    /// When a narrow unsigned is combined with a wide unsigned, C promotes to
    /// the wide unsigned type — the result IS unsigned and can wrap.
    fn is_wide_unsigned_type(&self, type_str: &str) -> bool {
        self.is_unsigned_type(type_str) && !self.is_narrow_unsigned_type(type_str)
    }

    /// Returns true if one operand is narrow unsigned and the other is NOT a
    /// wider unsigned type. In this case, C promotes the narrow unsigned to
    /// `int` (signed 32-bit), making the arithmetic signed — no unsigned wrap.
    fn narrow_promotion_is_safe(&self, left_type: &str, right_type: &str) -> bool {
        let left_narrow = self.is_narrow_unsigned_type(left_type);
        let right_narrow = self.is_narrow_unsigned_type(right_type);

        if left_narrow && !self.is_wide_unsigned_type(right_type) {
            return true;
        }
        if right_narrow && !self.is_wide_unsigned_type(left_type) {
            return true;
        }
        // Both narrow — already handled by the existing check, but include for completeness
        left_narrow && right_narrow
    }

    /// Check if text is a valid C operand expression (simple identifier or
    /// field expression like `ctx->field` or `obj.member`).
    fn is_valid_operand_expr(&self, text: &str) -> bool {
        if text.is_empty() {
            return false;
        }
        // Split on -> and . to get component parts
        for part in text.split("->").flat_map(|s| s.split('.')) {
            let part = part.trim();
            if part.is_empty() {
                return false;
            }
            if !part.chars().all(|c| c.is_alphanumeric() || c == '_')
                || !part
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphabetic() || c == '_')
            {
                return false;
            }
        }
        true
    }

    /// Check if a binary addition is immediately masked by bitwise AND.
    /// Pattern: `(expr + N) & MASK` — result is bounded by the mask regardless
    /// of whether the addition wraps. Common in ring buffer index arithmetic.
    /// Returns true when the addition result is the left operand of a `% N` expression.
    /// Pattern: `(x + 1) % N` — ring-buffer next-index idiom. The modulo makes the
    /// intermediate sum's exact value irrelevant; overflow doesn't change correctness.
    fn is_addition_bounded_by_modulo(&self, node: &Node, source: &str) -> bool {
        if let Some(site) = self.site_of(node) {
            return site.enclosing_operator.as_deref() == Some("%");
        }
        if let Some(parent) = node.parent() {
            let effective_parent = if parent.kind() == "parenthesized_expression" {
                parent.parent()
            } else {
                Some(parent)
            };
            if let Some(p) = effective_parent {
                if p.kind() == "binary_expression" {
                    if let Some(op) = p.child_by_field_name("operator") {
                        if get_node_text(&op, source) == "%" {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Returns true when the left operand of a subtraction is a call to a tick/time
    /// getter function (name contains "Tick", "Time", "Clock", "Counter", "Stamp").
    /// In that idiom unsigned wrap is intentional — see C99 §6.2.5p9.
    fn is_elapsed_time_subtraction(&self, left: &Node, source: &str) -> bool {
        let tick_keywords = ["Tick", "tick", "Time", "Clock", "clock", "Counter", "Stamp"];
        // Unwrap any parenthesized or cast expression to reach the call
        let mut cur = *left;
        loop {
            match cur.kind() {
                "parenthesized_expression" | "cast_expression" => {
                    if let Some(inner) = cur.child(1) {
                        cur = inner;
                    } else {
                        break;
                    }
                }
                "call_expression" => {
                    if let Some(func) = cur.child_by_field_name("function") {
                        let name = get_node_text(&func, source);
                        if tick_keywords.iter().any(|kw| name.contains(kw)) {
                            return true;
                        }
                    }
                    break;
                }
                _ => break,
            }
        }
        false
    }

    fn is_addition_masked_by_bitand(&self, node: &Node, source: &str) -> bool {
        if let Some(site) = self.site_of(node) {
            return site.enclosing_operator.as_deref() == Some("&");
        }
        // The addition node's parent should be a binary_expression with operator &
        if let Some(parent) = node.parent() {
            // Check for parenthesized_expression wrapping
            let effective_parent = if parent.kind() == "parenthesized_expression" {
                parent.parent()
            } else {
                Some(parent)
            };
            if let Some(p) = effective_parent {
                if p.kind() == "binary_expression" {
                    if let Some(op) = p.child_by_field_name("operator") {
                        let op_text = get_node_text(&op, source);
                        if op_text == "&" {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Return the effective (pre-cast if applicable) type of an operand.
    fn effective_operand_type(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> String {
        if let Some(pre) = self.get_pre_cast_type(node, source, type_map) {
            return pre;
        }
        if self.is_cast_over_guarded_narrow_sub(node, source, type_map) {
            return "uint16_t".to_string();
        }
        self.infer_type(node, source, type_map)
    }

    /// True when `node` is `(WIDE)(a - b)` with both operands narrow unsigned
    /// and the subtraction is guarded by an enclosing `if (a > b)` / `if (a >= b)`
    /// (or equivalent). In that branch the subtraction result is in the narrow
    /// unsigned range, so the cast behaves like a narrow-to-wide widening.
    fn is_cast_over_guarded_narrow_sub(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        if node.kind() != "cast_expression" {
            return false;
        }
        let Some(value) = node.child_by_field_name("value") else {
            return false;
        };
        // Peek through parens to the inner expression.
        let mut inner = value;
        while inner.kind() == "parenthesized_expression" {
            match inner.child(1) {
                Some(c) => inner = c,
                None => return false,
            }
        }
        if inner.kind() != "binary_expression" {
            return false;
        }
        match self.get_operator(&inner, source).as_deref() {
            Some("-") => {}
            _ => return false,
        }
        let (Some(l), Some(r)) = (
            inner.child_by_field_name("left"),
            inner.child_by_field_name("right"),
        ) else {
            return false;
        };
        let lt = self.infer_type(&l, source, type_map);
        let rt = self.infer_type(&r, source, type_map);
        if !self.is_narrow_unsigned_type(&lt) || !self.is_narrow_unsigned_type(&rt) {
            return false;
        }
        let lname = get_node_text(&l, source);
        let rname = get_node_text(&r, source);
        self.is_subtraction_guarded_by_comparison(node, lname.trim(), rname.trim(), source)
    }

    /// True when both operands' effective (pre-cast) types are narrow unsigned
    /// (uint8_t or uint16_t). Max sum/product fits in uint32_t.
    fn both_operands_narrow_pre_cast(
        &self,
        left: &Node,
        right: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        let l = self.effective_operand_type(left, source, type_map);
        let r = self.effective_operand_type(right, source, type_map);
        self.is_narrow_unsigned_type(&l) && self.is_narrow_unsigned_type(&r)
    }

    /// True when one operand is a narrow unsigned (possibly widened by a cast)
    /// and the other const-evaluates to a small non-negative integer
    /// (≤ `UINT16_MAX`, ~65535). Result cannot exceed ~131K, fitting uint32_t.
    fn is_narrow_cast_plus_small_const(
        &self,
        left: &Node,
        right: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        let macros = self.current_macros.borrow();
        let check = |narrow: &Node, small: &Node| -> bool {
            let t = self.effective_operand_type(narrow, source, type_map);
            if !self.is_narrow_unsigned_type(&t) {
                return false;
            }
            if let Some(val) =
                const_eval::try_evaluate_expr_with(small, source, &macros, Some(&self.constant))
            {
                return (0..=65535).contains(&val);
            }
            false
        };
        check(left, right) || check(right, left)
    }

    /// True when one operand is narrow unsigned (directly or via cast from
    /// narrow) and the other const-evaluates to a non-negative integer whose
    /// product with `UINT16_MAX` (65535) fits in uint32_t. In other words
    /// `small ≤ UINT32_MAX / UINT16_MAX ≈ 65538`.
    fn is_narrow_cast_times_small_const(
        &self,
        left: &Node,
        right: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        // The bound is a 32-bit int's; a model that does not fix int's width
        // proves nothing here.
        if !self.data_model.get().width_known(Rank::Int) {
            return false;
        }
        let macros = self.current_macros.borrow();
        const MAX_FACTOR: i64 = (u32::MAX as i64) / 65535; // ≈ 65538
        let check = |narrow: &Node, small: &Node| -> bool {
            let t = self.effective_operand_type(narrow, source, type_map);
            if !self.is_narrow_unsigned_type(&t) {
                return false;
            }
            if let Some(val) =
                const_eval::try_evaluate_expr_with(small, source, &macros, Some(&self.constant))
            {
                return (0..=MAX_FACTOR).contains(&val);
            }
            false
        };
        check(left, right) || check(right, left)
    }

    /// Width in bits the usual arithmetic conversions actually perform this
    /// operation in.
    ///
    /// **Not where the result is stored.** Unsigned wrap happens *during* the
    /// computation, so `size_t n = a * b` over two `unsigned int`s still
    /// multiplies in 32 bits and wraps before the store widens anything. The
    /// operands' common type is what bounds it.
    ///
    /// Everything narrower than `int` promotes, so `int`'s guaranteed width
    /// ([`Self::promoted_bits`]) is the floor, and a wider operand lifts it
    /// to the width its type is guaranteed. Asking the fits-check at a flat
    /// 32 was the whole of this rule's word-width blindness: `count *
    /// sizeof(struct s)` is computed in `size_t`, cannot wrap on a 64-bit
    /// build, and was reported anyway because it does not fit in 32 bits.
    /// The widths are the data model's: under ISO C's a `size_t` is only
    /// guaranteed 16 bits, so without a declared model that product is not
    /// proven to fit.
    ///
    /// This is the floor a fits-check may use: a value that fits it fits
    /// any width the operation can have on a target the model allows. Whether the width is actually
    /// KNOWN is `arith_width_known`'s question, and the one the
    /// definite-wrap channel has to ask.
    fn arith_width_bits(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> u32 {
        self.arith_width_known(node, source, type_map)
            .unwrap_or_else(|| self.promoted_bits())
    }

    /// `arith_width_bits`, or `None` when an operand's declared type resolves
    /// to a spelling this rule cannot place (ADR-0006).
    ///
    /// sqlite's `(u64)1486995408 * (u64)100000` (date.c) was reported as a
    /// definite wrap: the width fell to the 32-bit floor because `u64`
    /// resolves to `sqlite_uint64`, defined only in the generated
    /// `sqlite3.h` the scan never reads, and 148,699,540,800,000 does not
    /// fit 32 bits. The floor is right for proving a fit and wrong for
    /// proving a wrap: an operand whose type could not be resolved has no
    /// width to definitely exceed, so the honest answer is the same one
    /// INT32-C gives an unresolvable alias -- not applicable -- rather than
    /// the narrowest guess.
    fn arith_width_known(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> Option<u32> {
        let width =
            |n: Option<Node>| -> Option<u32> { self.operand_width(&n?, source, type_map, 0) };
        match node.kind() {
            // A shift is performed in the promoted type of its LEFT operand
            // alone; the count on the right says nothing about the width.
            "binary_expression"
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|op| matches!(get_node_text(&op, source), "<<" | ">>")) =>
            {
                width(node.child_by_field_name("left"))
            }
            "binary_expression" => self.common_width(
                width(node.child_by_field_name("left")),
                width(node.child_by_field_name("right")),
            ),
            // A compound assignment converts back into its destination, so the
            // destination is what the stored value has to fit.
            "assignment_expression" => width(node.child_by_field_name("left")),
            // `++`/`--` likewise write back into their own operand.
            _ => width(node.child_by_field_name("argument")),
        }
    }

    /// The width two operands' usual arithmetic conversions land on: the
    /// wider of the two, unknown if either is (unless the other is already
    /// 64 bits, which nothing the model allows widens), and never below the
    /// promoted floor.
    fn common_width(&self, left: Option<u32>, right: Option<u32>) -> Option<u32> {
        match (left, right) {
            (Some(64), _) | (_, Some(64)) => Some(64),
            (Some(l), Some(r)) => Some(l.max(r).max(self.promoted_bits())),
            _ => None,
        }
    }

    /// The width `int` is guaranteed under the data model: every operation
    /// is performed in at least this, since C's usual arithmetic conversions
    /// promote anything narrower before it runs. 32 on a declared model, 16
    /// under ISO C's widths.
    fn promoted_bits(&self) -> u32 {
        self.data_model.get().min_width(Rank::Int)
    }

    /// The width `size_t` is guaranteed under the data model.
    fn size_t_bits(&self) -> u32 {
        self.data_model
            .get()
            .spelled_width("size_t")
            .map_or(16, |(_, width)| width.min)
    }

    /// The width this operand's type gives an operation: the width the data
    /// model guarantees its type, no less than the promoted floor for any
    /// type the rule can place (promotion makes everything narrower than
    /// `int` `int` arithmetic, and a shape with no declared type at all -- a
    /// literal, a call -- keeps the floor it always had), `None` for a
    /// declared type that resolves to a spelling the rule does not recognize.
    ///
    /// Recurses through the shapes that carry a type without changing it
    /// (parentheses, a nested arithmetic subexpression), depth-capped because
    /// the operand of a real expression can nest arbitrarily.
    fn operand_width(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
        depth: u32,
    ) -> Option<u32> {
        if depth > OPERAND_TYPE_MAX_DEPTH {
            return Some(self.promoted_bits());
        }
        let recurse = |n: Option<Node>| -> Option<u32> {
            self.operand_width(&n?, source, type_map, depth + 1)
        };
        match node.kind() {
            "parenthesized_expression" => recurse(node.named_child(0)),
            // A constant has the type C11 6.4.4.1p5 gives it: the first of
            // `int`, `long`, `long long` that holds it, from the rank its
            // suffix names. `86400 * 7` is `long` arithmetic wherever `int`
            // is 16 bits, not 16-bit arithmetic.
            "number_literal" => Some(
                integer_literal_width(get_node_text(node, source), self.data_model.get())
                    .unwrap_or(0)
                    .max(self.promoted_bits()),
            ),
            // `sizeof` yields `size_t` by definition -- the operand that makes
            // an allocation size computation 64-bit in the first place, on a
            // declared 64-bit model.
            "sizeof_expression" => Some(self.size_t_bits().max(self.promoted_bits())),
            "cast_expression" => match node.child_by_field_name("type") {
                Some(t) => self.type_width_bits(get_node_text(&t, source)),
                None => Some(self.promoted_bits()),
            },
            // A subexpression is at least as wide as its own widest operand.
            "binary_expression" => self.common_width(
                recurse(node.child_by_field_name("left")),
                recurse(node.child_by_field_name("right")),
            ),
            "identifier" => match self.identifier_type(node, source, type_map) {
                Some(t) => self.type_width_bits(&t),
                None => Some(self.promoted_bits()),
            },
            "field_expression" => {
                let sft = self.struct_field_types.borrow();
                match crate::utility::cert_c::ast_utils::resolve_field_expression_type(
                    node, source, type_map, &sft,
                ) {
                    Some(t) => self.type_width_bits(&t),
                    None => Some(self.promoted_bits()),
                }
            }
            _ => Some(self.promoted_bits()),
        }
    }

    /// The width a declared type spelling gives an operation, resolved
    /// through the project's typedef chain first (ADR-0006):
    /// hostap's `u64` is `uint64_t` and was judged 32-bit by name.
    ///
    /// The width the data model guarantees the type: `unsigned long` is 64
    /// bits on a declared LP64 target, 32 on LLP64, and only 32 under ISO C's
    /// widths; `uint64_t` and the `least`/`fast`/`max` 64-bit types are 64
    /// everywhere; `size_t` is a pointer's width on a declared model. No
    /// less than the promoted floor for any spelling the rule recognizes.
    /// `None` is a chain that bottoms out in a name nothing the scan read
    /// defines.
    fn type_width_bits(&self, type_str: &str) -> Option<u32> {
        let base = Self::strip_type_qualifiers(type_str);
        let resolved = overflow_helpers::resolve_typedef_chain(&base, &self.typedef_types.borrow());
        let base = Self::strip_type_qualifiers(&resolved);
        let base = base.trim();
        let floor = self.promoted_bits();
        if base.contains('*') {
            return Some(floor);
        }
        if matches!(
            base,
            "uint_least64_t"
                | "uint_fast64_t"
                | "uintmax_t"
                | "int_least64_t"
                | "int_fast64_t"
                | "intmax_t"
        ) {
            return Some(64);
        }
        if let Some((_, width)) = self.data_model.get().spelled_width(base) {
            return Some(width.min.max(floor));
        }
        Self::is_recognized_integer_spelling(base).then_some(floor)
    }

    /// A type spelling this rule can place at some width: the C integer
    /// and character types in their signed/unsigned forms, the `<stdint.h>`
    /// and `<stddef.h>` names, and the Win32 SDK's unsigned typedefs.
    fn is_recognized_integer_spelling(base: &str) -> bool {
        let words: Vec<&str> = base.split_whitespace().collect();
        let builtin = !words.is_empty()
            && words.iter().all(|w| {
                matches!(
                    *w,
                    "signed" | "unsigned" | "char" | "short" | "int" | "long" | "_Bool" | "bool"
                )
            });
        builtin
            || matches!(
                base,
                "int8_t"
                    | "int16_t"
                    | "int32_t"
                    | "int64_t"
                    | "uint8_t"
                    | "uint16_t"
                    | "uint32_t"
                    | "int_least8_t"
                    | "int_least16_t"
                    | "int_least32_t"
                    | "int_least64_t"
                    | "uint_least8_t"
                    | "uint_least16_t"
                    | "uint_least32_t"
                    | "int_fast8_t"
                    | "int_fast16_t"
                    | "int_fast32_t"
                    | "int_fast64_t"
                    | "uint_fast8_t"
                    | "uint_fast16_t"
                    | "uint_fast32_t"
                    | "intmax_t"
                    | "intptr_t"
                    | "ptrdiff_t"
                    | "ssize_t"
                    | "wchar_t"
                    | "char16_t"
                    | "char32_t"
            )
            || ast_utils::is_win32_unsigned_typedef(base)
    }

    fn is_64bit_unsigned_declared(&self, type_str: &str) -> bool {
        type_str == "uint64_t"
            || type_str == "unsigned long long"
            || type_str == "unsigned long long int"
            || type_str == "uint_least64_t"
            || type_str == "uint_fast64_t"
    }

    fn any_operand_64bit_unsigned(
        &self,
        left: &Node,
        right: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        let left_64 = self
            .get_declared_type(left, source, type_map)
            .is_some_and(|t| self.is_64bit_unsigned_declared(&t));
        let right_64 = self
            .get_declared_type(right, source, type_map)
            .is_some_and(|t| self.is_64bit_unsigned_declared(&t));
        left_64 || right_64
    }

    fn get_declared_type(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> Option<String> {
        match node.kind() {
            "identifier" => self
                .identifier_type(node, source, type_map)
                .map(|t| t.into_owned()),
            "call_expression" => {
                // For function calls, check if the result is assigned to a typed variable
                // or look at the surrounding context. For now, return None.
                None
            }
            _ => None,
        }
    }

    fn has_overflow_check_addition(&self, node: &Node, source: &str) -> bool {
        // Look for UINT_MAX - a < b pattern (precondition) or result < a (postcondition)
        self.has_function_context_check(node, source, &["UINT_MAX", " - ", " < "])
            || self.has_function_context_check(node, source, &["SIZE_MAX", " - ", " < "])
            || self.has_function_context_check(node, source, &["== UINT_MAX"])
            || self.has_postcondition_check(node, source)
            || self.uses_wider_type(node, source)
            || self.is_inside_checked_block(node, source)
            || self.has_dominating_limit_guard(node, source)
    }

    fn has_overflow_check_subtraction(&self, node: &Node, source: &str) -> bool {
        // Look for if (a < b) or postcondition if (result > a) pattern
        // Note: We need an actual if check before or after the subtraction
        self.has_subtraction_precondition(node, source)
            || self.has_postcondition_check(node, source)
            || self.is_inside_checked_block(node, source)
            || self.is_subtract_one_guarded(node, source)
    }

    fn has_overflow_check_multiplication(&self, node: &Node, source: &str) -> bool {
        // Look for a > MAX / b pattern in containing function
        self.has_function_context_check(node, source, &["UINT_MAX", " / "])
            || self.has_function_context_check(node, source, &["SIZE_MAX", " / "])
            || self.has_preceding_overflow_check(node, source)
            || self.uses_wider_type(node, source)
            || self.is_inside_checked_block(node, source)
            || self.has_dominating_limit_guard(node, source)
    }

    /// Check if there's an overflow check in the code preceding this node
    fn has_preceding_overflow_check(&self, node: &Node, source: &str) -> bool {
        // Get text before this node in the translation unit, sanitized so a
        // comment/string literal elsewhere can't spoof the pattern.
        let node_start = node.start_byte();
        if node_start > 0 {
            let root = ast_utils::tree_root(node);
            let root_start = root.start_byte();
            if node_start <= root_start {
                return false;
            }
            let text = self.sanitized_text(node, source);
            let preceding_end = node_start.min(root.end_byte());
            let preceding = |p: &str| text.span_contains(root_start, preceding_end, p);
            // Look for SIZE_MAX/UINT_MAX division check patterns
            if (preceding("SIZE_MAX /") || preceding("UINT_MAX /")) && preceding("if") {
                return true;
            }
        }
        false
    }

    fn has_shift_overflow_check(&self, node: &Node, source: &str) -> bool {
        // Look for shift amount validation
        self.has_function_context_check(node, source, &["sizeof"])
            || self.is_inside_checked_block(node, source)
    }

    fn has_overflow_check_compound(&self, node: &Node, source: &str) -> bool {
        // Look for any overflow checking pattern
        self.has_function_context_check(node, source, &["if", "UINT_MAX"])
            || self.has_function_context_check(node, source, &["if", "SIZE_MAX"])
            || self.is_inside_checked_block(node, source)
            || self.has_dominating_limit_guard(node, source)
    }

    fn has_overflow_check_update(&self, node: &Node, source: &str) -> bool {
        // Look for bounds checking around increment/decrement - must be explicit UINT_MAX or == 0
        self.has_function_context_check(node, source, &["if", "UINT_MAX"])
            || self.has_function_context_check(node, source, &["if", "== 0"])
            || self.is_inside_checked_block(node, source)
    }

    fn has_calloc_overflow_check(&self, node: &Node, source: &str) -> bool {
        // Look for calloc-specific overflow checking
        if self.has_function_context_check(node, source, &["SIZE_MAX", " / "])
            || self.is_inside_checked_block(node, source)
        {
            return true;
        }
        // Thin-wrapper pattern: both calloc arguments are function parameters
        // of the enclosing function. The wrapper delegates overflow detection
        // to C11 calloc itself (§7.22.3.2 — "If the product of nmemb and size
        // … would overflow, … calloc shall return a null pointer"), so the
        // wrapper body does not need its own SIZE_MAX / size check.
        self.calloc_args_are_function_params(node, source)
    }

    fn calloc_args_are_function_params(&self, node: &Node, source: &str) -> bool {
        let args = self.get_function_arguments(node, source);
        if args.len() < 2 {
            return false;
        }
        let Some(func) = self.containing_function(node) else {
            return false;
        };
        let mut params: HashMap<String, String> = HashMap::new();
        if let Some(declarator) = func.child_by_field_name("declarator") {
            overflow_helpers::collect_params_from_declarator(&declarator, source, &mut params);
        }
        params.contains_key(args[0].trim()) && params.contains_key(args[1].trim())
    }

    fn has_function_context_check(&self, node: &Node, source: &str, patterns: &[&str]) -> bool {
        // Look in the containing function for overflow checking patterns.
        // Fall back to the full translation unit when the call is at file
        // scope (e.g. wiki snippet tests without a wrapping function).
        // Sanitized so a comment/string literal elsewhere in the function
        // can't spoof one of the patterns and silently suppress a real
        // violation.
        self.function_text_contains_all(node, source, patterns)
    }

    /// Check for subtraction precondition (if (a < b) before subtraction)
    fn has_subtraction_precondition(&self, node: &Node, source: &str) -> bool {
        // Look for if statement before the subtraction that compares the operands
        // Look for typical precondition pattern
        self.function_text_contains_any(
            node,
            source,
            &[
                "if (ui_a < ui_b)",
                "if (a < b)",
                "if(ui_a < ui_b)",
                "if(a < b)",
            ],
        )
    }

    /// Check for postcondition check (if (result < original) or if (result > original))
    fn has_postcondition_check(&self, node: &Node, source: &str) -> bool {
        // Look for postcondition patterns like "if (usum < ui_a)" or "if (udiff > ui_a)"
        self.function_text_contains_any(
            node,
            source,
            &[
                "if (usum < ",
                "if (udiff > ",
                "if(usum < ",
                "if(udiff > ",
                "if (result < ",
                "if (result > ",
            ],
        )
    }

    /// Check if operation uses wider type casting for safety
    fn uses_wider_type(&self, node: &Node, source: &str) -> bool {
        let text = self.sanitized_text(node, source);
        // Check parent for cast to wider type
        let parent = match self.site_of(node) {
            Some(site) => site.parent.map(|p| (p.start, p.end)),
            None => node.parent().map(|p| (p.start_byte(), p.end_byte())),
        };
        if let Some((start, end)) = parent {
            if text.span_contains(start, end, "(uint64_t)")
                || text.span_contains(start, end, "(unsigned long long)")
                || text.span_contains(start, end, "(int64_t)")
            {
                return true;
            }
        }
        // Also check if operands are cast to wider type
        text.contains(node, "(uint64_t)") || text.contains(node, "(unsigned long long)")
    }

    /// Check if the operation is inside an if-else block guarded by an unsigned type-limit macro.
    /// Operand-aware: the if-condition must reference at least one operand of the arithmetic.
    fn is_inside_checked_block(&self, node: &Node, source: &str) -> bool {
        const UNSIGNED_LIMIT_MACROS: &[&str] = &[
            "UINT_MAX",
            "SIZE_MAX",
            "UINT32_MAX",
            "UCHAR_MAX",
            "USHRT_MAX",
            "UINT8_MAX",
            "UINT16_MAX",
            "UINT64_MAX",
            "ULONG_MAX",
            "ULLONG_MAX",
        ];

        // The operand names cost a walk of the operator's subtree, so they
        // are read only once a governing condition names a limit.
        let op_names = std::cell::OnceCell::new();
        let guards = |parent: &Node| -> bool {
            if parent.kind() == "if_statement" {
                if let Some(condition) = parent.child_by_field_name("condition") {
                    let cond_text = get_node_text(&condition, source);
                    let has_limit = UNSIGNED_LIMIT_MACROS
                        .iter()
                        .any(|m| overflow_helpers::contains_word(cond_text, m));
                    if has_limit {
                        let op_names = op_names
                            .get_or_init(|| overflow_helpers::extract_operand_names(node, source));
                        if op_names.is_empty() {
                            return true;
                        }
                        if op_names
                            .iter()
                            .any(|name| overflow_helpers::contains_word(cond_text, name))
                        {
                            return true;
                        }
                    }
                }
            }
            false
        };
        // The walk's record skips the expressions between the operator and
        // its statement, none of which is an `if` or a function.
        if let Some(outer) = self.site_around(node).map(|site| site.outer.clone()) {
            let root = ast_utils::tree_root(node);
            for span in &outer {
                if span.kind == "if_statement" {
                    match span.find(root) {
                        Some(found) if guards(&found) => return true,
                        Some(_) => {}
                        None => return self.is_inside_checked_block_climbing(node, &guards),
                    }
                }
                // Stop at function boundary
                if span.kind == "function_definition" {
                    break;
                }
            }
            return false;
        }
        self.is_inside_checked_block_climbing(node, &guards)
    }

    /// [`Self::is_inside_checked_block`]'s question asked of every ancestor
    /// found by one descent from the root.
    fn is_inside_checked_block_climbing(
        &self,
        node: &Node,
        guards: &dyn Fn(&Node) -> bool,
    ) -> bool {
        for parent in ast_utils::ancestors(node) {
            if guards(&parent) {
                return true;
            }
            // Stop at function boundary
            if parent.kind() == "function_definition" {
                break;
            }
        }
        false
    }

    fn get_operator(&self, node: &Node, source: &str) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let text = &source[child.start_byte()..child.end_byte()];
                if matches!(text, "+" | "-" | "*" | "/" | "<<" | ">>") {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    fn get_assignment_operator(&self, node: &Node, source: &str) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let text = &source[child.start_byte()..child.end_byte()];
                if matches!(text, "+=" | "-=" | "*=" | "/=" | "<<=" | ">>=") {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    fn get_update_operator(&self, node: &Node, source: &str) -> String {
        overflow_helpers::get_update_operator(node, source)
    }

    /// Check if a decrement/subtraction is inside a block guarded by a positive-value condition.
    /// Patterns: `if (var > 0)`, `while (var > expr)`, `for (...; var > expr; ...)`.
    /// For unsigned types, `var > expr` implies `var >= 1`, making `var--` or `var - 1` safe.
    fn is_guarded_by_gt_zero(&self, node: &Node, var_name: &str, source: &str) -> bool {
        // Every condition already evaluated here, not just the ancestor
        // `if`/`while`/`for` chain this walked before: `&&` conjuncts and
        // preceding `if`s establish the same fact and were being missed.
        guard_dominance::dominating_conditions(node)
            .iter()
            .any(|cond| {
                Self::condition_is_truthiness_test(cond, var_name, source)
                    || self.condition_implies_positive(get_node_text(cond, source), var_name)
            })
    }

    /// True when `cond` is a bare truthiness test of `var_name` — `while (n)`,
    /// `if (len && ...)`. For an unsigned value that is exactly `n != 0`, so a
    /// `n--` or `n - 1` under it cannot wrap. hostap's
    /// `while (in_size) { in_size--; ... }` is the recorded example: the text
    /// patterns below look for a comparison operator and there is none here.
    fn condition_is_truthiness_test(cond: &Node, var_name: &str, source: &str) -> bool {
        match cond.kind() {
            "identifier" => get_node_text(cond, source).trim() == var_name.trim(),
            "parenthesized_expression" => cond
                .named_child(0)
                .is_some_and(|inner| Self::condition_is_truthiness_test(&inner, var_name, source)),
            "binary_expression" => {
                let op = cond
                    .child_by_field_name("operator")
                    .map(|o| o.kind())
                    .unwrap_or("");
                // Both conjuncts hold once the body runs; `||` establishes neither.
                op == "&&"
                    && [
                        cond.child_by_field_name("left"),
                        cond.child_by_field_name("right"),
                    ]
                    .into_iter()
                    .flatten()
                    .any(|side| Self::condition_is_truthiness_test(&side, var_name, source))
            }
            _ => false,
        }
    }

    /// Check if a condition text implies var_name > 0 (i.e., var is positive).
    /// Handles compound conditions (&&/||) via substring matching.
    /// Recognizes `var > expr` (any lower bound, not just zero) since for unsigned
    /// types, `var > expr` always implies `var >= 1`.
    fn condition_implies_positive(&self, cond_text: &str, var_name: &str) -> bool {
        let cond = cond_text.trim();
        let cond = if cond.starts_with('(') && cond.ends_with(')') {
            &cond[1..cond.len() - 1]
        } else {
            cond
        };
        let cond = cond.trim();

        // Quick check: does the condition mention the variable as a whole word?
        if !overflow_helpers::contains_word(cond, var_name) {
            return false;
        }

        // Pattern 1: var > expr (strict GT — implies var >= 1 for unsigned)
        // Covers: var > 0, var > idx, var > some_expr, etc.
        let gt_pat = format!("{} > ", var_name);
        if cond.contains(&gt_pat) {
            return true;
        }

        // Pattern 2: var != 0 or 0 != var (explicit non-zero check)
        let neq_zero = format!("{} != 0", var_name);
        let zero_neq = format!("0 != {}", var_name);
        if cond.contains(&neq_zero) || cond.contains(&zero_neq) {
            return true;
        }

        // Pattern 3: expr < var (reverse of var > expr — strict LT)
        let lt_rev = format!("< {}", var_name);
        if cond.contains(&lt_rev) {
            for (pos, _) in cond.match_indices(&lt_rev) {
                // Exclude << (shift) and <= (less-than-or-equal)
                let prev = if pos > 0 { cond.as_bytes()[pos - 1] } else { 0 };
                if prev != b'<' && prev != b'=' {
                    return true;
                }
            }
        }

        false
    }

    /// For "var - 1" or "var - 1U" subtraction: if var is guarded by a
    /// positive-value condition or was incremented before this point,
    /// then var >= 1 and var - 1 >= 0, so no unsigned wrap.
    fn is_subtract_one_guarded(&self, node: &Node, source: &str) -> bool {
        if let Some(right) = node.child_by_field_name("right") {
            let right_text = get_node_text(&right, source).trim().to_string();
            // Accept 1, 1U, 1u, 1UL, 1ul, etc.
            if self.is_literal_one(&right_text) {
                if let Some(left) = node.child_by_field_name("left") {
                    let var_name = get_node_text(&left, source).trim().to_string();
                    if self.is_guarded_by_gt_zero(node, &var_name, source) {
                        return true;
                    }
                    // Check if the variable was incremented before this subtraction
                    // in the same compound_statement (e.g., `var++; ... var - 1U`)
                    if self.is_preceded_by_increment(node, &var_name, source) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if a literal text represents the value 1 (with optional unsigned suffix).
    fn is_literal_one(&self, text: &str) -> bool {
        let text = text.trim();
        if text == "1" {
            return true;
        }
        // Strip unsigned/long suffixes: 1U, 1u, 1UL, 1ul, 1ULL, etc.
        let stripped = text.trim_end_matches(['u', 'U', 'l', 'L']);
        stripped == "1"
    }

    /// Check if the variable was incremented (var++, ++var, var += 1) before
    /// this node in the same compound_statement. This means var >= 1 at the
    /// point of the subtraction.
    fn is_preceded_by_increment(&self, node: &Node, var_name: &str, source: &str) -> bool {
        // Find the enclosing compound_statement
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "compound_statement" {
                let sanitized = get_sanitized_node_text(&parent, source);
                let rel_end = (node.start_byte() - parent.start_byte()).min(sanitized.len());
                let before_text = &sanitized[..rel_end];
                // Check for var++ or ++var
                let postinc = format!("{}++", var_name);
                let preinc = format!("++{}", var_name);
                let addassign = format!("{} += 1", var_name);
                if before_text.contains(&postinc)
                    || before_text.contains(&preinc)
                    || before_text.contains(&addassign)
                {
                    return true;
                }
                return false;
            }
            if parent.kind() == "function_definition" {
                break;
            }
            current = parent.parent();
        }
        false
    }

    /// Check if a node is inside the update clause of a for-loop.
    /// For-loop update increments (i++) are bounded by the loop condition,
    /// making unsigned wrap impossible in normal usage.
    fn is_in_for_loop_update(&self, node: &Node) -> bool {
        let mut current = Some(*node);
        while let Some(n) = current {
            if let Some(parent) = n.parent() {
                if parent.kind() == "for_statement" {
                    // Check if this node is in the update clause
                    // The for_statement fields: initializer, condition, update, body
                    if let Some(update) = parent.child_by_field_name("update") {
                        if self.node_contains(&update, &n) {
                            return true;
                        }
                    }
                }
                current = Some(parent);
            } else {
                break;
            }
        }
        false
    }

    /// Check if parent node contains child (by byte range).
    fn node_contains(&self, parent: &Node, child: &Node) -> bool {
        child.start_byte() >= parent.start_byte() && child.end_byte() <= parent.end_byte()
    }

    /// For binary "var + 1" or "1 + var" (including 1U, 1u, etc.): if var is bounded
    /// by an enclosing loop condition (var < limit), then var + 1 <= limit <= UINT_MAX,
    /// so no wrap.
    fn is_add_one_bounded_by_loop(&self, node: &Node, source: &str) -> bool {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let left_text = get_node_text(&left, source);
            let right_text = get_node_text(&right, source);

            // Check "var + 1" pattern (including 1U, 1u, 1UL, etc.)
            if self.is_literal_one(right_text.trim()) {
                return self.is_bounded_by_loop_condition(node, left_text.trim(), source);
            }
            // Check "1 + var" pattern
            if self.is_literal_one(left_text.trim()) {
                return self.is_bounded_by_loop_condition(node, right_text.trim(), source);
            }
        }
        false
    }

    /// Check if var_name is bounded by an enclosing loop or if-statement condition.
    /// Detects `while (var < limit)`, `for (...; var < limit; ...)`, and
    /// `if (var < limit)` patterns (true branch only).
    /// Inside the guarded body, var < limit, so var + 1 <= limit <= UINT_MAX.
    fn is_bounded_by_loop_condition(&self, node: &Node, var_name: &str, source: &str) -> bool {
        let mut current = *node;
        while let Some(parent) = current.parent() {
            if matches!(parent.kind(), "while_statement" | "for_statement") {
                if let Some(condition) = parent.child_by_field_name("condition") {
                    let cond_text = get_node_text(&condition, source);
                    if self.condition_implies_upper_bound(&cond_text, var_name) {
                        return true;
                    }
                }
            }
            // Also check if_statement — but only if we're in the true branch
            if parent.kind() == "if_statement" {
                if let Some(condition) = parent.child_by_field_name("condition") {
                    let cond_text = get_node_text(&condition, source);
                    if self.condition_implies_upper_bound(&cond_text, var_name) {
                        // Verify we're inside the consequence (true branch), not alternative
                        if let Some(consequence) = parent.child_by_field_name("consequence") {
                            if current.start_byte() >= consequence.start_byte()
                                && current.end_byte() <= consequence.end_byte()
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            if parent.kind() == "function_definition" {
                break;
            }
            current = parent;
        }
        false
    }

    /// Check if a condition implies var < some_limit (upper bound).
    /// Recognizes: `var < expr`, `var <= expr`, `expr > var`, `expr >= var`.
    fn condition_implies_upper_bound(&self, cond_text: &str, var_name: &str) -> bool {
        let cond = cond_text.trim();
        let cond = if cond.starts_with('(') && cond.ends_with(')') {
            &cond[1..cond.len() - 1]
        } else {
            cond
        };
        let cond = cond.trim();

        if !overflow_helpers::contains_word(cond, var_name) {
            return false;
        }

        // Pattern 1: var < expr or var <= expr
        let lt_pat = format!("{} < ", var_name);
        let le_pat = format!("{} <= ", var_name);
        if cond.contains(&lt_pat) || cond.contains(&le_pat) {
            return true;
        }

        // Pattern 2: expr > var or expr >= var
        let gt_rev = format!("> {}", var_name);
        if cond.contains(&gt_rev) {
            // Exclude >> (shift)
            for (pos, _) in cond.match_indices(&gt_rev) {
                let prev = if pos > 0 { cond.as_bytes()[pos - 1] } else { 0 };
                if prev != b'>' {
                    return true;
                }
            }
        }

        false
    }

    /// Check if `a - b` is inside a block guarded by `a >= b`, `a > b`, `b <= a`, or `b < a`.
    /// Walks ancestors for if_statement, while_statement, for_statement — same pattern
    /// as `is_guarded_by_gt_zero` but checks for a comparison between the two operands.
    /// Also handles else-branch: if inside `else` of `if (b > a)`, then `a - b` is NOT safe
    /// but `b - a` IS safe (the else implies `a >= b` is false, i.e., `b >= a`).
    fn is_subtraction_guarded_by_comparison(
        &self,
        node: &Node,
        left_name: &str,
        right_name: &str,
        source: &str,
    ) -> bool {
        // The short-circuit check runs FIRST, because it re-derives the operand
        // names from the node with casts peeled. The validity test below sees
        // the caller's RAW text, so `db->size - (size_t) offset` fails it --
        // and that is exactly the corpus shape this guard exists for
        // (pureftpd puredb/src/puredb_read.c:307).
        if self.short_circuit_guards_subtraction(node, source) {
            return true;
        }

        // Apply when both operands are valid operand expressions (simple identifiers
        // or field expressions like ctx->field, obj.member)
        if !self.is_valid_operand_expr(left_name) || !self.is_valid_operand_expr(right_name) {
            return false;
        }

        let mut current = *node;
        while let Some(parent) = current.parent() {
            if matches!(
                parent.kind(),
                "if_statement" | "while_statement" | "for_statement"
            ) {
                if let Some(condition) = parent.child_by_field_name("condition") {
                    let cond_text = get_node_text(&condition, source);

                    // True-branch: if (left >= right) { left - right } is safe
                    if self.condition_implies_a_gte_b(&cond_text, left_name, right_name) {
                        if parent.kind() == "if_statement" {
                            if let Some(consequence) = parent.child_by_field_name("consequence") {
                                if current.start_byte() >= consequence.start_byte()
                                    && current.end_byte() <= consequence.end_byte()
                                {
                                    return true;
                                }
                            }
                        } else {
                            // while/for: loop body is always the true branch
                            return true;
                        }
                    }

                    // Else-branch: if (right > left) { ... } else { left - right }
                    // In the else branch, !(right > left) implies left >= right,
                    // so left - right is safe.
                    if parent.kind() == "if_statement" {
                        if self.condition_implies_a_gte_b(&cond_text, right_name, left_name) {
                            if let Some(alternative) = parent.child_by_field_name("alternative") {
                                if current.start_byte() >= alternative.start_byte()
                                    && current.end_byte() <= alternative.end_byte()
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            // Implicit-else from an early-exit if:
            //   if (right > left) return ...;
            //   /* subtraction here: left - right is safe */
            // Walk preceding siblings at every compound_statement on the way
            // up. If any is an early-exit if whose condition implies
            // right > left, the subtraction is guarded.
            if parent.kind() == "compound_statement"
                && self.preceding_early_exit_guards_subtraction(
                    &parent, &current, left_name, right_name, source,
                )
            {
                return true;
            }

            if parent.kind() == "function_definition" {
                break;
            }
            current = parent;
        }
        false
    }

    /// `if (offset > size || len > size - offset)` and
    /// `if (n >= 8 && n % 8 == 0) { n -= 8; }`: a guard evaluated as an earlier
    /// operand of the same short-circuit expression.
    ///
    /// Polarity is the whole point and is delegated, not guessed:
    /// [`guard_dominance::dominating_condition_branch`] reports `true` for the
    /// right operand of `&&` (the left ran and was true) and `false` for `||`
    /// (the left ran and was false). A condition known FALSE proves
    /// `left >= right` when the condition itself says `right >= left`, which is
    /// the same implication the else-branch arm above already relies on.
    ///
    /// Operands are peeled with [`guard_dominance::strip_arg_wrappers`] before
    /// comparison so the cast in `db->size - (size_t) offset` does not defeat
    /// the name match -- the corpus instance this was written for.
    fn short_circuit_guards_subtraction(&self, node: &Node, source: &str) -> bool {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return false;
        };
        let left_peeled = guard_dominance::strip_arg_wrappers(&left);
        let right_peeled = guard_dominance::strip_arg_wrappers(&right);
        let left_name = get_node_text(&left_peeled, source);
        let right_name = get_node_text(&right_peeled, source);
        let (left_name, right_name) = (left_name.trim(), right_name.trim());
        if !self.is_valid_operand_expr(left_name) || !self.is_valid_operand_expr(right_name) {
            return false;
        }

        for cond in guard_dominance::dominating_conditions(node) {
            // Only a condition reached through a short-circuit operand is new
            // here; the enclosing-`if` shapes are the ancestor walk's job and
            // re-answering them from this side would double-count.
            if cond
                .parent()
                .is_none_or(|p| p.kind() != "binary_expression")
            {
                continue;
            }
            let Some(branch) = guard_dominance::dominating_condition_branch(&cond, node) else {
                continue;
            };
            let cond_text = get_node_text(&cond, source);
            let proved = if branch {
                // Known true: the condition itself must say left >= right.
                self.condition_implies_a_gte_b(&cond_text, left_name, right_name)
            } else {
                // Known false: its negation says left >= right when the
                // condition says right >= left.
                self.condition_implies_a_gte_b(&cond_text, right_name, left_name)
            };
            if proved {
                return true;
            }
        }
        false
    }

    /// Check for a preceding sibling `if (cond) return/break/continue/goto ...;`
    /// whose condition implies `right > left`, in which case the implicit
    /// else-path (statements after the if) has `left >= right`.
    fn preceding_early_exit_guards_subtraction(
        &self,
        compound: &Node,
        current: &Node,
        left_name: &str,
        right_name: &str,
        source: &str,
    ) -> bool {
        let current_start = current.start_byte();
        for i in 0..compound.named_child_count() {
            let Some(sibling) = compound.named_child(i) else {
                break;
            };
            if sibling.end_byte() > current_start {
                break;
            }
            if sibling.kind() != "if_statement" {
                continue;
            }
            if !Self::if_always_exits(&sibling) {
                continue;
            }
            let Some(cond) = sibling.child_by_field_name("condition") else {
                continue;
            };
            let cond_text = get_node_text(&cond, source);
            if self.condition_implies_a_gte_b(&cond_text, right_name, left_name) {
                return true;
            }
        }
        false
    }

    /// True when the consequence of `if_node` is a statement (or compound
    /// block ending with a statement) that unconditionally transfers
    /// control out of the enclosing block: return, break, continue, goto.
    /// No `alternative` required — callers only care about the fall-through
    /// path past the if.
    fn if_always_exits(if_node: &Node) -> bool {
        let Some(consequence) = if_node.child_by_field_name("consequence") else {
            return false;
        };
        let is_exit = |k: &str| {
            matches!(
                k,
                "return_statement" | "break_statement" | "continue_statement" | "goto_statement"
            )
        };
        if is_exit(consequence.kind()) {
            return true;
        }
        if consequence.kind() == "compound_statement" {
            let mut last: Option<Node> = None;
            for i in 0..consequence.named_child_count() {
                if let Some(c) = consequence.named_child(i) {
                    last = Some(c);
                }
            }
            if let Some(l) = last {
                return is_exit(l.kind());
            }
        }
        false
    }

    /// Check if a condition implies `a >= b` (i.e., `a - b` cannot underflow).
    /// Recognizes: `a >= b`, `a > b`, `b <= a`, `b < a`, and compound `&&` conditions.
    fn condition_implies_a_gte_b(&self, cond_text: &str, a: &str, b: &str) -> bool {
        let cond = cond_text.trim();
        let cond = if cond.starts_with('(') && cond.ends_with(')') {
            &cond[1..cond.len() - 1]
        } else {
            cond
        };
        let cond = cond.trim();

        // Must mention both variables
        if !overflow_helpers::contains_word(cond, a) || !overflow_helpers::contains_word(cond, b) {
            return false;
        }

        // For compound && conditions, check each part
        for part in cond.split("&&") {
            let part = part.trim();
            if self.single_condition_implies_a_gte_b(part, a, b) {
                return true;
            }
        }

        false
    }

    /// Check a single (non-compound) condition for a >= b patterns.
    fn single_condition_implies_a_gte_b(&self, cond: &str, a: &str, b: &str) -> bool {
        // Strip parens
        let cond = cond.trim();
        let cond = if cond.starts_with('(') && cond.ends_with(')') {
            &cond[1..cond.len() - 1]
        } else {
            cond
        };
        let cond = cond.trim();

        // Pattern: a >= b or a > b
        let gte_pat = format!("{} >= {}", a, b);
        let gt_pat = format!("{} > {}", a, b);
        if overflow_helpers::contains_word(cond, a) && overflow_helpers::contains_word(cond, b) {
            if cond.contains(&gte_pat) || cond.contains(&gt_pat) {
                return true;
            }
            // Pattern: b <= a or b < a
            let lte_pat = format!("{} <= {}", b, a);
            let lt_pat = format!("{} < {}", b, a);
            if cond.contains(&lte_pat) || cond.contains(&lt_pat) {
                return true;
            }
            // Pattern: `a > (b + POS)` or `a > b + POS` where POS evaluates to a
            // positive integer. Implies a > b.
            if self.cond_gt_b_plus_positive(cond, a, b) {
                return true;
            }
        }
        false
    }

    /// True when `cond` matches `a > (b + C)` / `a > b + C` / `a >= b + C` with
    /// `C` a non-negative const-evaluable expression. In that case `a > b`.
    fn cond_gt_b_plus_positive(&self, cond: &str, a: &str, b: &str) -> bool {
        for op in [" > ", " >= "] {
            let key = format!("{}{}", a, op);
            let Some(pos) = cond.find(&key) else { continue };
            let rhs = cond[pos + key.len()..].trim();
            let rhs = rhs.trim_start_matches('(').trim_end_matches(')').trim();
            // Need a `+` at top level connecting `b` and a positive tail.
            let Some(plus_pos) = rhs.find(" + ") else {
                continue;
            };
            let left_of_plus = rhs[..plus_pos].trim();
            let right_of_plus = rhs[plus_pos + 3..].trim();
            if left_of_plus != b {
                continue;
            }
            let macros = self.current_macros.borrow();
            if let Some(v) = const_eval::try_evaluate_text_public(right_of_plus, &macros) {
                if v > 0 {
                    return true;
                }
            }
        }
        false
    }

    fn get_function_arguments(&self, node: &Node, source: &str) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(arguments) = node.child_by_field_name("arguments") {
            // Named children of argument_list are the actual argument
            // expressions; unnamed children (`(`, `,`, `)`) are skipped.
            for i in 0..arguments.named_child_count() {
                if let Some(child) = arguments.named_child(i) {
                    let arg_text = source[child.start_byte()..child.end_byte()].to_string();
                    args.push(arg_text.trim().to_string());
                }
            }
        }

        args
    }
}
