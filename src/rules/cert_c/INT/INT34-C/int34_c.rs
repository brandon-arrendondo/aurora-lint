// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::FunctionCfg;
use crate::analyze::const_eval::{self, MacroConstantMap, VarRangeMap};
use crate::analyze::context::ProjectContext;
use crate::analyze::context::ScopedTable;
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::macro_expand::{self, FunctionMacro};
use crate::analyze::value_range::{self, RangeAnalysisResult};
use crate::manifest::Severity;
use crate::settings::{AnalysisSettings, IntFacts};
use crate::utility::cert_c::ast_utils;
use crate::utility::cert_c::data_model::{IntWidth, Rank};
use crate::utility::cert_c::declarator_utils;
use crate::utility::cert_c::expr_type;
use crate::utility::cert_c::overflow_helpers::resolve_typedef_chain;
use lang_parsing_substrate::query;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

pub struct Int34C {
    project_macros: RefCell<Arc<MacroConstantMap>>,
    current_macros: RefCell<MacroConstantMap>,
    /// Per-function CFGs
    function_cfgs: RefCell<Arc<HashMap<usize, FunctionCfg>>>,
    /// Per-function VRA results
    vra_results: RefCell<Arc<HashMap<usize, RangeAnalysisResult>>>,
    /// Every `#define NAME ...` name seen across the pre-scanned project,
    /// object-like and function-like alike. A shift amount naming one of
    /// these is a compile-time constant even when its replacement text
    /// can't be folded to an integer.
    project_macro_names: RefCell<Arc<HashSet<String>>>,
    /// Function-like macro names from the pre-scanned project, so a shift
    /// amount written as `MASK(n)` is recognized as a macro invocation
    /// rather than an opaque call.
    project_function_macro_names: RefCell<HashSet<String>>,
    /// The same macros with their replacement lists, for the expansion pass:
    /// a bound that only exists inside a `#define` (`IDR0_NUMSIDB_VAL(v)`
    /// masking `v` down to four bits) is invisible until the invocation is
    /// expanded.
    project_function_macros: RefCell<Arc<HashMap<String, FunctionMacro>>>,
    /// `project_function_macros` plus the file under analysis, per-file
    /// winning -- the same merge `current_macros` does for object-like
    /// macros, and needed for the same reason: a `#define` private to one
    /// `.c` file never reaches the project scan, which only walks the header
    /// directories.
    current_function_macros: RefCell<HashMap<String, FunctionMacro>>,
    /// Pre-scanned callee summaries, consulted for shift amounts written as a
    /// call: `return_range` bounds the amount when the returns fold.
    function_summaries: RefCell<ScopedTable<FunctionSummary>>,
    /// The subset of `function_summaries` whose every return expression is a
    /// compile-time constant, pre-projected into the name set
    /// `const_eval::ConstantNameSets` wants.
    constant_returning_functions: RefCell<HashSet<String>>,
    /// Project-wide typedef alias map, walked by
    /// `overflow_helpers::resolve_typedef_chain` so a left operand declared
    /// `vptr_t` reaches `unsigned long` and is measured at 64 bits, not the
    /// 32-bit floor an unrecognized spelling falls back to.
    typedef_types: RefCell<Arc<HashMap<String, String>>>,
    /// The integer data model the settings credit: how wide a shifted
    /// operand is guaranteed to be.
    data_model: Cell<IntFacts>,
}

/// How deep [`Int34C::resolve_operand_width`] follows an operand through
/// parentheses, subscripts and arithmetic before calling its type unknown,
/// and how many block-scope typedefs it follows. Without it a
/// machine-generated sum thousands of terms deep ran the rule past its time
/// limit. Past this depth the operand is untyped like any other the rule
/// cannot type, so findings can only drop.
const OPERAND_TYPE_DEPTH: usize = 32;

/// A type spelling with qualifiers and storage class dropped.
fn strip_type_qualifiers(text: &str) -> String {
    text.split_whitespace()
        .filter(|t| {
            !matches!(
                *t,
                "const" | "volatile" | "static" | "extern" | "register" | "_Atomic" | "restrict"
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// What a typedef name visible at a use denotes, when a block enclosing the
/// use defines it.
enum BlockTypedef<'a> {
    /// `typedef T name;`: the definition, and its type `T` as spelled.
    Alias(Node<'a>, String),
    /// A pointer, array or function type under that name: not an integer.
    Other,
}

/// The typedef `name` that a use at `at` sees from an enclosing block: from
/// the innermost block outward, the last definition in that block before
/// the use. Preprocessor arms and `case` or labeled statements open no
/// scope, so a definition under one counts for its block; arms that leave
/// the name meaning different types, or defined in some builds and not in
/// others, make it unknown ([`BlockTypedef::Other`]). File scope is left to
/// the project-wide map. `None` when no enclosing block defines the name.
fn block_scope_typedef<'a>(at: &Node<'a>, name: &str, source: &str) -> Option<BlockTypedef<'a>> {
    let mut cur = at.parent();
    while let Some(block) = cur {
        if block.kind() == "compound_statement" {
            let mut reach = Reach {
                at: at.start_byte(),
                name,
                source,
                depth: 0,
                too_deep: false,
            };
            let mut seen = vec![Reaching::Undefined];
            reach.items(&scope_items(&block), &mut seen);
            if reach.too_deep {
                return Some(BlockTypedef::Other);
            }
            if seen.iter().all(|r| matches!(r, Reaching::Undefined)) {
                cur = block.parent();
                continue;
            }
            return Some(match seen.as_slice() {
                [Reaching::Alias(def, spelled)] => BlockTypedef::Alias(*def, spelled.clone()),
                _ => BlockTypedef::Other,
            });
        }
        cur = block.parent();
    }
    None
}

/// What a typedef name stands for after a run of block items, in one build.
#[derive(Clone)]
enum Reaching<'a> {
    /// No definition in this block yet: the enclosing scope's meaning.
    Undefined,
    /// `typedef T name;`, with `T` as spelled, qualifiers dropped.
    Alias(Node<'a>, String),
    /// A pointer, array or function type.
    Other,
}

/// The walk behind [`block_scope_typedef`]: the set of meanings `name` can
/// have at byte `at`, over every combination of preprocessor arms.
struct Reach<'s> {
    at: usize,
    name: &'s str,
    source: &'s str,
    depth: usize,
    too_deep: bool,
}

impl<'s> Reach<'s> {
    /// Apply `items`, in order, up to the use.
    fn items<'a>(&mut self, items: &[Node<'a>], seen: &mut Vec<Reaching<'a>>) {
        if self.depth > OPERAND_TYPE_DEPTH {
            self.too_deep = true;
            return;
        }
        self.depth += 1;
        for item in items {
            if item.start_byte() >= self.at {
                break;
            }
            let holds_use = item.end_byte() > self.at;
            match item.kind() {
                "type_definition" if !holds_use => {
                    if let Some(meaning) = self.definition(item) {
                        *seen = vec![meaning];
                    }
                }
                "case_statement" | "labeled_statement" => self.items(&scope_items(item), seen),
                "preproc_if" | "preproc_ifdef" => {
                    if holds_use {
                        // The arm holding the use is the one compiled with it.
                        if let Some(arm) = arms(item).into_iter().find(|arm| {
                            arm.child_by_field_name("alternative")
                                .is_none_or(|alt| self.at < alt.start_byte())
                        }) {
                            self.items(&scope_items(&arm), seen);
                        }
                    } else {
                        let before = seen.clone();
                        let mut after = Vec::new();
                        let mut has_else = false;
                        for arm in arms(item) {
                            has_else |= arm.kind() == "preproc_else";
                            let mut taken = before.clone();
                            self.items(&scope_items(&arm), &mut taken);
                            after.extend(taken);
                        }
                        if !has_else {
                            after.extend(before);
                        }
                        *seen = merge(after);
                    }
                }
                _ => {}
            }
            if holds_use {
                break;
            }
        }
        self.depth -= 1;
    }

    /// What `def` makes `name` mean, when it defines `name`.
    fn definition<'a>(&self, def: &Node<'a>) -> Option<Reaching<'a>> {
        let declarator = declarator_utils::typedef_declarators(def)
            .into_iter()
            .find(|d| {
                declarator_utils::TypedefShape::of(d, self.source)
                    .name
                    .as_deref()
                    == Some(self.name)
            })?;
        if declarator.kind() != "type_identifier" {
            return Some(Reaching::Other);
        }
        let ty = def.child_by_field_name("type")?;
        Some(Reaching::Alias(
            *def,
            strip_type_qualifiers(ast_utils::get_node_text(&ty, self.source)),
        ))
    }
}

/// The meanings in `all` with duplicates dropped: one per spelling, keeping
/// the last definition.
fn merge(all: Vec<Reaching<'_>>) -> Vec<Reaching<'_>> {
    let mut out: Vec<Reaching<'_>> = Vec::new();
    for r in all {
        let same = out.iter().position(|o| match (o, &r) {
            (Reaching::Undefined, Reaching::Undefined) | (Reaching::Other, Reaching::Other) => true,
            (Reaching::Alias(_, a), Reaching::Alias(_, b)) => a == b,
            _ => false,
        });
        match same {
            Some(i) => out[i] = r,
            None => out.push(r),
        }
    }
    out
}

/// An `#if`/`#ifdef` chain's arms in order: the group itself, then each
/// `#elif`/`#elifdef`/`#else` reached through `alternative`.
fn arms<'a>(group: &Node<'a>) -> Vec<Node<'a>> {
    let mut out = vec![*group];
    let mut cur = *group;
    while let Some(alt) = cur.child_by_field_name("alternative") {
        out.push(alt);
        cur = alt;
    }
    out
}

/// The items a block, arm, `case` or labeled statement holds: its named
/// children, less a condition, name, `case` value, label or the next arm.
fn scope_items<'a>(node: &Node<'a>) -> Vec<Node<'a>> {
    let skip: Vec<usize> = ["condition", "name", "alternative", "value", "label"]
        .iter()
        .filter_map(|f| node.child_by_field_name(f))
        .map(|n| n.id())
        .collect();
    let mut cursor = node.walk();
    let found: Vec<Node<'a>> = node
        .named_children(&mut cursor)
        .filter(|c| !skip.contains(&c.id()))
        .collect();
    found
}

impl Int34C {
    pub fn new() -> Self {
        Self {
            project_macros: RefCell::new(Arc::new(MacroConstantMap::new())),
            current_macros: RefCell::new(MacroConstantMap::new()),
            function_cfgs: RefCell::new(Arc::default()),
            vra_results: RefCell::new(Arc::default()),
            project_macro_names: RefCell::new(Arc::new(HashSet::new())),
            project_function_macro_names: RefCell::new(HashSet::new()),
            project_function_macros: RefCell::new(Arc::new(HashMap::new())),
            current_function_macros: RefCell::new(HashMap::new()),
            function_summaries: RefCell::default(),
            constant_returning_functions: RefCell::new(HashSet::new()),
            typedef_types: RefCell::new(Arc::new(HashMap::new())),
            data_model: Cell::new(IntFacts::default()),
        }
    }
}

impl CertRule for Int34C {
    fn reads_header_facts(&self) -> bool {
        true
    }

    fn rule_id(&self) -> &'static str {
        "INT34-C"
    }

    fn description(&self) -> &'static str {
        "Do not shift an expression by a negative number of bits or by greater than or equal to the number of bits that exist in the operand"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "INT34-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_macros.borrow_mut() = context.macro_constants.clone();
        *self.project_macro_names.borrow_mut() = context.defined_macro_names.clone();
        *self.project_function_macro_names.borrow_mut() =
            context.function_macros.keys().cloned().collect();
        *self.project_function_macros.borrow_mut() = context.function_macros.clone();
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.constant_returning_functions.borrow_mut() = context
            .function_summaries
            .iter()
            .filter(|(_, summary)| summary.returns_only_compile_time_constants)
            .map(|(name, _)| name.clone())
            .collect();
        *self.typedef_types.borrow_mut() = context.typedef_types.clone();
    }

    fn set_visible_types(&self, types: &crate::analyze::context::VisibleTypes) {
        *self.typedef_types.borrow_mut() = types.typedef_types.clone();
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        self.data_model.set(settings.facts);
    }

    fn set_function_cfgs(&self, cfgs: &Arc<HashMap<usize, FunctionCfg>>) {
        *self.function_cfgs.borrow_mut() = Arc::clone(cfgs);
    }

    fn set_vra_results(&self, results: &Arc<HashMap<usize, RangeAnalysisResult>>) {
        *self.vra_results.borrow_mut() = Arc::clone(results);
    }

    fn needs_vra(&self) -> bool {
        true
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Merge project-level macros with per-file macros (per-file wins)
        *self.current_macros.borrow_mut() = const_eval::merged_macro_constants(
            &self.project_macros.borrow(),
            node,
            source,
            self.data_model.get(),
        );

        let mut fmacros = HashMap::clone(&self.project_function_macros.borrow());
        fmacros.extend(macro_expand::collect_function_macros(node, source));
        *self.current_function_macros.borrow_mut() = fmacros;

        self.check_recursive(node, source, &mut violations);
        violations
    }
}

impl Int34C {
    fn check_recursive(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Whether each node is in a preprocessor condition is carried down
        // the walk, not climbed to from every operator.
        for (binary_node, preproc) in ast_utils::descendants_of_kinds_with(
            *node,
            &["binary_expression"],
            ast_utils::InPreprocCondition::default(),
            ast_utils::InPreprocCondition::step,
        ) {
            // `#if (1 << 40) > 0` is evaluated by the preprocessor, whose
            // arithmetic is in intmax_t (C11 6.10.1p4): there is no `int`
            // operand for the amount to exceed. The guarded body is ordinary
            // code and stays checked.
            if preproc.holds(binary_node) {
                continue;
            }
            if let Some(operator) = ast_utils::get_binary_operator(&binary_node, source) {
                if operator == "<<" || operator == ">>" {
                    self.check_shift_operation(&binary_node, source, operator, violations);
                }
            }
        }
    }

    /// Check if a shift operation is safe
    fn check_shift_operation(
        &self,
        node: &Node,
        source: &str,
        _operator: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let left = node.child_by_field_name("left");
        let right = node.child_by_field_name("right");

        if let (Some(left_node), Some(right_node)) = (left, right) {
            let right_text = ast_utils::get_node_text(&right_node, source);
            let left_text = ast_utils::get_node_text(&left_node, source);

            // The bound every range gate below compares against: the
            // precision of the LEFT operand once promoted (CERT INT34-C uses
            // precision, not width). C11 6.5.7p3 makes the hazard relative
            // to that operand, so a 64-bit operand shifted by [32, 63] is
            // defined behaviour and must not be reported as if it were
            // `uint32_t`.
            let width = self.operand_precision(&left_node, source);

            // A constant amount -- a literal, a `#define`, an enumerator,
            // `sizeof`, or arithmetic over those -- is judged by its value
            // when that folds to one. One that does not fold (its macro
            // lives in a header the scan did not read) cannot be judged and
            // is left alone rather than guessed at.
            //
            // The value is held to the operand's precision only when the
            // operand's type is known: the `int` floor above is a safe bound
            // for a proof that a varying amount fits, but reporting `x >> 32`
            // against it would assert a 32-bit `x` the rule never saw -- a
            // `uint64_t` struct field, or a typedef whose header spells it
            // through a macro. An operand of unknown type is reported only
            // for an amount no standard integer type can take.
            if self.is_non_negative_integer_literal(&right_node, source)
                || self.is_compile_time_constant(&right_node, source)
            {
                let folded = const_eval::try_evaluate_range(
                    &right_node,
                    source,
                    &self.current_macros.borrow(),
                    &VarRangeMap::new(),
                );
                if let Some(value) = folded.filter(|r| r.min == r.max).map(|r| r.min) {
                    let known = self.resolved_operand_precision(&left_node, source);
                    let bound = known.unwrap_or_else(|| {
                        i64::from(self.data_model.get().min_width(Rank::LongLong))
                    });
                    if value < 0 || value >= bound {
                        self.report_constant_amount(
                            node,
                            &right_node,
                            value,
                            known.is_some().then_some(bound),
                            source,
                            violations,
                        );
                    }
                }
                return;
            }

            // If the shift amount contains a modulo operation with a small
            // constant (e.g. `(pos + bi) % 8u`), the result is always bounded
            // to [0, modulus-1] — guaranteed within type width for any standard
            // integer type.
            if self.shift_amount_bounded_by_modulo(&right_node, source) {
                return;
            }

            // An explicit bitmask clamp on the shift amount — `(n - g) &
            // MASK(wordRadix)`, `bit & 31` — is the compliant idiom CERT's
            // own solution uses, and the one real code writes when it has
            // already thought about this exact hazard.
            if self.shift_amount_masked(&right_node, source) {
                return;
            }

            // The amount is a call whose pre-scanned return range is already
            // within any standard operand's width.
            if self.shift_amount_bounded_by_callee_return(&right_node, source, width) {
                return;
            }

            // Try CFG-based VRA first (more precise)
            if let Some(range) = self.eval_shift_range_via_vra(node, &right_node, source) {
                // A shift amount bounded below the operand's width is safe.
                if Self::range_within_width(&range, width) {
                    return;
                }
            }

            // Fallback: syntactic const_eval range analysis on the shift amount.
            {
                let macros = self.current_macros.borrow();
                let mut var_ranges = const_eval::extract_loop_var_ranges(node, source, &macros);
                Self::extract_if_condition_ranges(node, source, &macros, &mut var_ranges);

                if let Some(range) =
                    const_eval::try_evaluate_range(&right_node, source, &macros, &var_ranges)
                {
                    // Same logic: an amount bounded below the width is safe.
                    if Self::range_within_width(&range, width) {
                        return;
                    }
                }
            }

            // Last pass before reporting: redo the range analysis with the
            // project's function-like macros expanded, and with every local
            // the amount names resolved to whatever it was last assigned.
            // Both are ordinary ways for a real bound to sit one hop away
            // from the shift -- a register field extracted by a `#define`
            // that masks it, or that extraction parked in a local on the
            // line above -- and neither is reachable from the shift
            // expression alone.
            if self.shift_amount_bounded_after_expansion(node, &right_node, source, width) {
                return;
            }

            // Check if this is an unsigned type operation. Unsigned shifts
            // avoid the signed-overflow hazard that makes `<<` on signed
            // types especially dangerous, but the shift COUNT itself being
            // negative or >= the operand's bit width is undefined behavior
            // regardless of direction or signedness (C11 6.5.7p3) --
            // verified against CERT's own "Compliant Solution (Right
            // Shift)" example, which adds the same PRECISION() bound check
            // to an unsigned `>>`. So both operators require validation
            // for both signed and unsigned operands.
            if self.is_likely_unsigned(left_text, &left_node, source) {
                if !self.is_shift_amount_validated(node, &right_node, source, width) {
                    self.report_violation(
                        node,
                        left_text.to_string(),
                        right_text.to_string(),
                        source,
                        violations,
                    );
                }
            } else {
                // For signed types or unknown types, require validation for both left and right shifts
                if !self.is_shift_amount_validated(node, &right_node, source, width) {
                    self.report_violation(
                        node,
                        left_text.to_string(),
                        right_text.to_string(),
                        source,
                        violations,
                    );
                }
            }
        }
    }

    fn report_violation(
        &self,
        node: &Node,
        _left_text: String,
        right_text: String,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let operation = ast_utils::get_node_text(node, source);

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message: format!(
                "Shift operation '{}' by '{}' without validating shift amount is non-negative and within type width",
                operation, right_text
            ),
            file_path: String::new(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            suggestion: Some(format!(
                "Check that '{}' is >= 0 and < the bit width of the operand before shifting",
                right_text
            )),
            ..Default::default()
        });
    }

    /// A constant amount whose folded `value` is negative or reaches the
    /// promoted operand's precision `bound`, or, with no `bound`, the width
    /// of every standard integer type.
    fn report_constant_amount(
        &self,
        node: &Node,
        amount: &Node,
        value: i64,
        bound: Option<i64>,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let operation = ast_utils::get_node_text(node, source);
        let amount_text = ast_utils::get_node_text(amount, source);
        let (message, suggestion) = match bound {
            Some(bound) => (
                format!(
                    "Shift operation '{}' by '{}' ({}) is outside [0, {}), the precision of its promoted left operand",
                    operation, amount_text, value, bound
                ),
                format!(
                    "Shift by less than {} bits, or shift a wider or unsigned operand",
                    bound
                ),
            ),
            None if value < 0 => (
                format!(
                    "Shift operation '{}' by '{}' ({}) is by a negative amount",
                    operation, amount_text, value
                ),
                "Shift by a non-negative amount".to_string(),
            ),
            None => (
                format!(
                    "Shift operation '{}' by '{}' ({}) reaches the width of every standard integer type",
                    operation, amount_text, value
                ),
                "Shift by less than the operand's precision".to_string(),
            ),
        };
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message,
            file_path: String::new(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            suggestion: Some(suggestion),
            ..Default::default()
        });
    }

    /// True if the shift amount is masked with a compile-time constant —
    /// `expr & M` (either operand order). `M` bounds the result to
    /// `[0, M]`, so a foldable mask is accepted only when it is small
    /// enough to be in range for any standard integer type (mirroring the
    /// modulo check below).
    ///
    /// A mask that is a compile-time constant sqc cannot *fold* (seL4's
    /// `MASK(wordRadix)`, whose `wordRadix` lives in a per-architecture
    /// header) is accepted as written. The clamp is deliberate and its
    /// width is fixed by the target, not by run-time data, which is the
    /// hazard class this rule exists to find.
    fn shift_amount_masked(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "parenthesized_expression" {
            return node
                .named_child(0)
                .is_some_and(|inner| self.shift_amount_masked(&inner, source));
        }
        if node.kind() != "binary_expression" {
            return false;
        }
        if ast_utils::get_binary_operator(node, source) != Some("&") {
            return false;
        }
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return false;
        };
        [left, right]
            .iter()
            .any(|mask| self.mask_bounds_shift_amount(mask, source))
    }

    /// One operand of an `&` acting as a bound on the shift amount.
    fn mask_bounds_shift_amount(&self, mask: &Node, source: &str) -> bool {
        if !self.is_compile_time_constant(mask, source) {
            return false;
        }
        let macros = self.current_macros.borrow();
        match const_eval::try_evaluate_expr(mask, source, &macros) {
            // Foldable: the mask is the exact upper bound of the amount.
            Some(value) => (0..=63).contains(&value),
            // Not foldable, but constant — see the doc comment above.
            None => true,
        }
    }

    /// True if the shift amount is fixed at compile time, in the weak sense
    /// [`const_eval::is_compile_time_constant_expr`] defines: the value need
    /// not fold, because "did it fold?" is a fact about sqc's include
    /// coverage, not about the code under analysis.
    fn is_compile_time_constant(&self, node: &Node, source: &str) -> bool {
        const_eval::is_compile_time_constant_expr(
            node,
            source,
            &self.current_macros.borrow(),
            const_eval::ConstantNameSets {
                object_macros: &self.project_macro_names.borrow(),
                function_macros: &self.project_function_macro_names.borrow(),
                constant_returning_functions: &self.constant_returning_functions.borrow(),
                file_macros: None,
            },
        )
    }

    /// The shift amount is a call to a pre-scanned function whose every
    /// return path provably lands in `[0, 31]` — safe for any standard
    /// integer operand, the same bound the VRA and const_eval paths use.
    ///
    /// Distinct from the constant case above: there the returns are fixed but
    /// unfoldable, here they fold to a range that may hold several values.
    fn shift_amount_bounded_by_callee_return(&self, node: &Node, source: &str, width: i64) -> bool {
        let node = if node.kind() == "parenthesized_expression" {
            match node.named_child(0) {
                Some(inner) => inner,
                None => return false,
            }
        } else {
            *node
        };
        if node.kind() != "call_expression" {
            return false;
        }
        let Some(callee) = node.child_by_field_name("function") else {
            return false;
        };
        if callee.kind() != "identifier" {
            return false;
        }
        let name = ast_utils::get_node_text(&callee, source);
        self.function_summaries
            .borrow()
            .get(name)
            .and_then(|summary| summary.return_range)
            .is_some_and(|range| range.min >= 0 && range.max < width)
    }

    /// Returns true if the shift amount expression is bounded by a modulo operation
    /// with a constant divisor that's within type width (e.g., `expr % 8u` gives 0-7).
    fn shift_amount_bounded_by_modulo(&self, node: &Node, source: &str) -> bool {
        // Direct modulo: `expr % N`
        if node.kind() == "binary_expression" {
            if let Some(op) = ast_utils::get_binary_operator(node, source) {
                if op == "%" {
                    if let Some(right) = node.child_by_field_name("right") {
                        if self.is_non_negative_integer_literal(&right, source) {
                            let text = ast_utils::get_node_text(&right, source)
                                .trim()
                                .to_ascii_lowercase();
                            let stripped = text.trim_end_matches(['u', 'l']);
                            if let Ok(modulus) = stripped.parse::<u64>() {
                                // modulus <= 64 means result is 0..modulus-1, within any type width
                                return modulus > 0 && modulus <= 64;
                            }
                        }
                    }
                }
            }
        }
        // Parenthesized: `(expr % N)`
        if node.kind() == "parenthesized_expression" {
            if let Some(inner) = node.child(1) {
                return self.shift_amount_bounded_by_modulo(&inner, source);
            }
        }
        false
    }

    /// Returns true if the node is a non-negative integer literal
    /// (decimal, hex, octal, or binary), including those with suffix letters
    /// such as `8u`, `16UL`, `0x1FUL`.
    fn is_non_negative_integer_literal(&self, node: &Node, source: &str) -> bool {
        // tree-sitter-c uses "number_literal" for all numeric constants.
        if node.kind() != "number_literal" {
            return false;
        }
        let text = ast_utils::get_node_text(node, source)
            .trim()
            .to_ascii_lowercase();
        // Strip common integer suffixes (u, l, ul, ull, lu, llu)
        let stripped = text.trim_end_matches(['u', 'l']);
        // Must be parseable as a non-negative integer (decimal, hex, octal)
        if let Some(hex) = stripped.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).is_ok()
        } else if let Some(bin) = stripped.strip_prefix("0b") {
            u64::from_str_radix(bin, 2).is_ok()
        } else if stripped.starts_with('0') && stripped.len() > 1 {
            u64::from_str_radix(&stripped[1..], 8).is_ok()
        } else {
            stripped.parse::<u64>().is_ok()
        }
    }

    /// Check if the operand is likely an unsigned type
    /// A shift amount range the operand can absorb: non-negative and
    /// entirely below `width`. A single value is no exception: a literal
    /// amount never reaches here (`is_compile_time_constant`), and a variable
    /// the analysis pins to one value (`unsigned i = 39; x >> i`) is as
    /// undefined at 39 as any range that reaches it.
    fn range_within_width(range: &const_eval::ValueRange, width: i64) -> bool {
        range.min >= 0 && range.max < width
    }

    /// Precision of the shift's left operand once promoted, as the bound
    /// every range gate compares against: the width its type is guaranteed
    /// under the data model (C11 5.2.4.2.1 unless one is declared), less the
    /// sign bit of a signed type. An operand narrower than `int` promotes to
    /// a signed `int`, so `c << 31` on a char has precision 31 on a 32-bit
    /// `int` and 15 under ISO C's 16.
    ///
    /// `int`'s guaranteed width is the floor, not a guess: an operand the
    /// rule cannot type (a struct field, a call, an unknown typedef) keeps
    /// the narrowest width, so widening is only ever the result of positive
    /// evidence. The reverse default would assert safety for `uint32_t x >>
    /// 40`. Its sign is not known either, and only a type shown to be
    /// signed loses the sign bit: an untyped `reg >> 31` is not reported on
    /// a guess. Under ISO C's widths that floor is 16 (`unsigned x >> 20` is
    /// undefined where `int` is 16 bits) and a `long` is 32; a declared LP64
    /// target makes them 32 and 64.
    fn operand_precision(&self, left: &Node, source: &str) -> i64 {
        self.resolved_operand_precision(left, source)
            .unwrap_or_else(|| i64::from(self.data_model.get().min_width(Rank::Int)))
    }

    /// The promoted left operand's precision when the rule can type it, and
    /// `None` when [`Self::operand_precision`] would fall back to the floor.
    fn resolved_operand_precision(&self, left: &Node, source: &str) -> Option<i64> {
        let (unsigned, w) = self.promoted_operand_width(left, source, 0)?;
        Some(i64::from(w.min) - i64::from(!unsigned))
    }

    /// The left operand's type after integer promotion: anything narrower
    /// than `int` becomes a signed `int`.
    fn promoted_operand_width(
        &self,
        node: &Node,
        source: &str,
        depth: usize,
    ) -> Option<(bool, IntWidth)> {
        let model = self.data_model.get();
        let (unsigned, w) = self.resolve_operand_width(node, source, 0, depth)?;
        if w.min < model.min_width(Rank::Int) {
            return Some((false, model.width_of(Rank::Int)));
        }
        Some((unsigned, w))
    }

    /// Whether the integer object `node` denotes is declared unsigned, and
    /// its declared width, after peeling `unwrap` pointer/array levels
    /// (`p[i]`, `*p`). `None` for anything the rule cannot resolve to an
    /// integer scalar, or nested more than [`OPERAND_TYPE_DEPTH`] deep.
    fn resolve_operand_width(
        &self,
        node: &Node,
        source: &str,
        unwrap: usize,
        depth: usize,
    ) -> Option<(bool, IntWidth)> {
        if depth > OPERAND_TYPE_DEPTH {
            return None;
        }
        let depth = depth + 1;
        match node.kind() {
            "parenthesized_expression" => {
                self.resolve_operand_width(&node.named_child(0)?, source, unwrap, depth)
            }
            "cast_expression" => {
                let ty = node.child_by_field_name("type")?;
                let text = ast_utils::get_node_text(&ty, source);
                if text.contains('*') {
                    return None;
                }
                self.width_of_type_text(text, &ty, source)
            }
            "number_literal" => {
                // `1ULL << n`, `0xffffffff << n`: a constant's suffix and
                // value fix its type (C11 6.4.4.1), so a hexadecimal constant
                // too large for `int` is an `unsigned int`.
                let model = self.data_model.get();
                let text = ast_utils::get_node_text(node, source);
                let (unsigned, rank) = expr_type::integer_literal_rank(text, model)?;
                Some((unsigned, model.width_of(rank)))
            }
            "identifier" => {
                let name = ast_utils::get_node_text(node, source);
                let (decl, mut declarator) =
                    ast_utils::resolve_identifier_declarator(node, name, source)?;
                for _ in 0..unwrap {
                    if !matches!(declarator.kind(), "pointer_declarator" | "array_declarator") {
                        return None;
                    }
                    declarator = declarator.child_by_field_name("declarator")?;
                }
                if declarator.kind() != "identifier" {
                    return None;
                }
                self.width_of_type_text(
                    &ast_utils::declaration_type_text(&decl, source),
                    &decl,
                    source,
                )
            }
            "subscript_expression" => {
                let arg = node.child_by_field_name("argument")?;
                self.resolve_operand_width(&arg, source, unwrap + 1, depth)
            }
            // `(x & 0xFF00000000000000ULL) >> 56`: an arithmetic or bitwise
            // result has the common type of its promoted operands, so both
            // must be known -- unless one is wider than every standard type,
            // which the other then converts to (`(__uint128_t)a * b`). A
            // shift's result is its promoted left operand.
            "binary_expression" if unwrap == 0 => {
                let op = ast_utils::get_binary_operator(node, source).unwrap_or_default();
                let left = node.child_by_field_name("left")?;
                match op {
                    "<<" | ">>" => self.promoted_operand_width(&left, source, depth),
                    "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" => {
                        let right = node.child_by_field_name("right")?;
                        let widest = self.data_model.get().min_width(Rank::LongLong);
                        let l = self.promoted_operand_width(&left, source, depth);
                        let r = self.promoted_operand_width(&right, source, depth);
                        if let Some(extended) = [l, r]
                            .into_iter()
                            .flatten()
                            .find(|(_, w)| w.rank.is_none() && w.min > widest)
                        {
                            return Some(extended);
                        }
                        let ((lu, lw), (ru, rw)) = (l?, r?);
                        Some(match lw.min.cmp(&rw.min) {
                            std::cmp::Ordering::Greater => (lu, lw),
                            std::cmp::Ordering::Less => (ru, rw),
                            std::cmp::Ordering::Equal => (lu || ru, lw),
                        })
                    }
                    _ => None,
                }
            }
            "pointer_expression" if ast_utils::is_dereference_expression(node, source) => {
                let arg = node.child_by_field_name("argument")?;
                self.resolve_operand_width(&arg, source, unwrap + 1, depth)
            }
            _ => None,
        }
    }

    /// Width of the type spelled `text` at `at`, with qualifiers and storage
    /// class dropped, as the data model knows it. A typedef name is first
    /// looked up in the blocks enclosing `at`, since a block-scope
    /// `typedef unsigned long long word;` hides a file-scope `word` of
    /// another width; past those it is followed project-wide.
    /// A bare `long` is 64 bits on LP64 and 32 on LLP64; unless a model is
    /// declared, only its guaranteed 32 is credited -- a shift safety claim
    /// has to be provable, not inferred from the target the benchmark
    /// happens to run on.
    fn width_of_type_text(&self, text: &str, at: &Node, source: &str) -> Option<(bool, IntWidth)> {
        let mut base = strip_type_qualifiers(text);
        let mut at = *at;
        for _ in 0..OPERAND_TYPE_DEPTH {
            if base.contains(char::is_whitespace) {
                break;
            }
            match block_scope_typedef(&at, &base, source) {
                Some(BlockTypedef::Alias(def, spelled)) => {
                    base = strip_type_qualifiers(&spelled);
                    at = def;
                }
                Some(BlockTypedef::Other) => return None,
                None => break,
            }
        }
        let resolved = resolve_typedef_chain(&base, &self.typedef_types.borrow());
        // GCC and Clang's 128-bit extended integer types, which no data
        // model spells.
        if resolved.contains("__int128") || resolved.contains("__uint128") {
            let unsigned = resolved.contains("unsigned") || resolved.contains("__uint128");
            return Some((
                unsigned,
                IntWidth {
                    rank: None,
                    min: 128,
                    max: Some(128),
                },
            ));
        }
        self.data_model.get().spelled_width(&resolved)
    }

    fn is_likely_unsigned(&self, var_name: &str, node: &Node, source: &str) -> bool {
        // Check common naming conventions for unsigned variables
        if var_name.starts_with("ui_")
            || var_name.starts_with("u_")
            || var_name.starts_with("unsigned_")
        {
            return true;
        }

        // Scope/shadowing-aware resolution: when `node` is a plain
        // identifier reference, resolve its actual binding (nearest
        // enclosing block declaration, correctly disambiguating shadowed
        // re-declarations of the same name in sibling/nested blocks) rather
        // than shallow-scanning only the function's top-level body, which
        // could misattribute across two nested blocks with a same-named
        // local of a different type.
        if node.kind() == "identifier" {
            if let Some(decl) =
                ast_utils::find_enclosing_declaration_for_identifier(node, var_name, source)
            {
                return self.decl_has_unsigned_var(&decl, var_name, source);
            }
            if let Some(func) = ast_utils::find_containing_function(node) {
                if ast_utils::is_function_parameter(&func, var_name, source) {
                    if let Some(param_list) = self.find_parameter_list(&func) {
                        for i in 0..param_list.child_count() {
                            if let Some(param) = param_list.child(i) {
                                if param.kind() == "parameter_declaration"
                                    && self.decl_has_unsigned_var(&param, var_name, source)
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
                return false;
            }
        }

        // Fallback for non-identifier operands (e.g. `arr[i] << n`, where
        // the left text isn't a bare identifier so the scoped lookup above
        // doesn't apply): the previous shallow scan over the function's
        // parameters and top-level body declarations.
        if let Some(func) = ast_utils::find_containing_function(node) {
            // Check function parameters via function_declarator → parameter_list
            if let Some(param_list) = self.find_parameter_list(&func) {
                for i in 0..param_list.child_count() {
                    if let Some(param) = param_list.child(i) {
                        if param.kind() == "parameter_declaration"
                            && self.decl_has_unsigned_var(&param, var_name, source)
                        {
                            return true;
                        }
                    }
                }
            }
            // Check local variable declarations in function body
            if let Some(body) = func.child_by_field_name("body") {
                if self.body_has_unsigned_var(&body, var_name, source) {
                    return true;
                }
            }
        }

        false
    }

    /// Find the parameter_list node within a function_definition.
    /// Traverses: function_definition → function_declarator → parameter_list
    fn find_parameter_list<'a>(&self, func: &'a Node) -> Option<Node<'a>> {
        for i in 0..func.child_count() {
            if let Some(child) = func.child(i) {
                if child.kind() == "function_declarator" {
                    for j in 0..child.child_count() {
                        if let Some(grandchild) = child.child(j) {
                            if grandchild.kind() == "parameter_list" {
                                return Some(grandchild);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if a declaration node declares `var_name` with an unsigned type.
    /// Works for both parameter_declaration and declaration nodes.
    fn decl_has_unsigned_var(&self, decl: &Node, var_name: &str, source: &str) -> bool {
        let mut has_unsigned = false;
        let mut declares_var = false;

        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                match child.kind() {
                    "sized_type_specifier" => {
                        let text = ast_utils::get_node_text(&child, source);
                        if ast_utils::is_unsigned_type(text) {
                            has_unsigned = true;
                        }
                    }
                    "identifier" if ast_utils::get_node_text(&child, source) == var_name => {
                        declares_var = true;
                    }
                    "pointer_declarator" | "array_declarator" | "init_declarator"
                        if self.declarator_contains_name(&child, var_name, source) =>
                    {
                        declares_var = true;
                    }
                    _ => {}
                }
            }
        }

        has_unsigned && declares_var
    }

    /// Recursively check if a declarator subtree contains an identifier matching var_name.
    fn declarator_contains_name(&self, node: &Node, var_name: &str, source: &str) -> bool {
        if node.kind() == "identifier" {
            return ast_utils::get_node_text(node, source) == var_name;
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if self.declarator_contains_name(&child, var_name, source) {
                    return true;
                }
            }
        }
        false
    }

    /// Walk a compound_statement looking for local declarations of var_name with unsigned type.
    fn body_has_unsigned_var(&self, body: &Node, var_name: &str, source: &str) -> bool {
        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                if child.kind() == "declaration"
                    && self.decl_has_unsigned_var(&child, var_name, source)
                {
                    return true;
                }
            }
        }
        false
    }

    /// Check if shift amount has been validated
    fn is_shift_amount_validated(
        &self,
        shift_node: &Node,
        shift_amount: &Node,
        source: &str,
        width: i64,
    ) -> bool {
        let shift_var = ast_utils::get_node_text(shift_amount, source);

        // Find the containing function
        if let Some(func) = ast_utils::find_containing_function(shift_node) {
            if let Some(body) = func.child_by_field_name("body") {
                // Check if there's validation before the shift
                if self.has_validation_check(&body, shift_var, source, shift_node) {
                    return true;
                }
            }
        }

        // Check parent if/while/for statements
        let mut current = shift_node.parent();
        while let Some(node) = current {
            match node.kind() {
                "if_statement" => {
                    if let Some(condition) = node.child_by_field_name("condition") {
                        if self.checks_shift_bounds(&condition, shift_var, source) {
                            if self.is_in_safe_branch(&node, shift_node) {
                                return true;
                            }
                        }
                    }
                }
                "while_statement" | "for_statement" | "do_statement" => {
                    // If the shift amount expression contains an identifier
                    // bounded by this loop condition to a small value, it's safe.
                    if let Some(condition) = node.child_by_field_name("condition") {
                        if self.loop_bounds_shift_amount(&condition, shift_amount, source, width) {
                            return true;
                        }
                    }
                }
                _ => {}
            }
            current = node.parent();
        }

        false
    }

    /// Check if a loop condition bounds the shift amount to a safe range.
    /// Extracts identifiers from the shift amount and checks if the loop
    /// condition constrains them below the operand's width.
    fn loop_bounds_shift_amount(
        &self,
        condition: &Node,
        shift_amount: &Node,
        source: &str,
        width: i64,
    ) -> bool {
        // Collect identifiers from the shift amount expression
        let mut shift_vars = Vec::new();
        Self::collect_identifiers_from(shift_amount, source, &mut shift_vars);
        if shift_vars.is_empty() {
            return false;
        }

        // Unwrap parenthesized_expression
        let cond = if condition.kind() == "parenthesized_expression" {
            match condition.child(1) {
                Some(c) => c,
                None => return false,
            }
        } else {
            *condition
        };

        // Check if any shift variable appears in a < or <= comparison with a small bound
        if self.condition_bounds_var_small(&cond, &shift_vars, source, width) {
            return true;
        }

        // Check for (expr >> var) != 0 pattern — this implicitly bounds var
        // to less than the bit width of expr (e.g., uint32_t → < 32).
        if self.condition_is_shift_to_zero_check(&cond, &shift_vars, source) {
            return true;
        }

        false
    }

    fn collect_identifiers_from(node: &Node, source: &str, names: &mut Vec<String>) {
        for id_node in query::find_descendants_of_kind(*node, "identifier") {
            let name = ast_utils::get_node_text(&id_node, source).to_string();
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }

    /// Check if a condition bounds any of the given variables to less than
    /// the operand's width.
    fn condition_bounds_var_small(
        &self,
        cond: &Node,
        var_names: &[String],
        source: &str,
        width: i64,
    ) -> bool {
        if cond.kind() != "binary_expression" {
            return false;
        }
        let op = ast_utils::get_binary_operator(cond, source).unwrap_or_default();

        // Handle && conditions
        if op == "&&" {
            if let Some(left) = cond.child_by_field_name("left") {
                if self.condition_bounds_var_small(&left, var_names, source, width) {
                    return true;
                }
            }
            if let Some(right) = cond.child_by_field_name("right") {
                if self.condition_bounds_var_small(&right, var_names, source, width) {
                    return true;
                }
            }
            return false;
        }

        // Check var < N or var <= N patterns
        let (left, right) = match (
            cond.child_by_field_name("left"),
            cond.child_by_field_name("right"),
        ) {
            (Some(l), Some(r)) => (l, r),
            _ => return false,
        };
        let left_text = ast_utils::get_node_text(&left, source);
        let right_text = ast_utils::get_node_text(&right, source);

        // var < BOUND or var <= BOUND
        if (op == "<" || op == "<=") && var_names.iter().any(|v| v == left_text) {
            // Try to parse the bound as a small number
            if let Ok(bound) = right_text.trim().parse::<i64>() {
                return bound <= width;
            }
            // Try to resolve macro
            let macros = self.current_macros.borrow();
            if let Some(val) = const_eval::try_evaluate_expr(&right, source, &macros) {
                return val <= width;
            }
        }

        // BOUND > var or BOUND >= var
        if (op == ">" || op == ">=") && var_names.iter().any(|v| v == right_text) {
            if let Ok(bound) = left_text.trim().parse::<i64>() {
                return bound <= width;
            }
            let macros = self.current_macros.borrow();
            if let Some(val) = const_eval::try_evaluate_expr(&left, source, &macros) {
                return val <= width;
            }
        }

        false
    }

    /// Recognize `(expr >> var) != 0` as implicitly bounding `var`.
    /// When a while-loop condition is `(mask >> bi) != 0u`, `bi` is bounded
    /// to less than the bit width of mask (at most 31 for uint32_t).
    fn condition_is_shift_to_zero_check(
        &self,
        cond: &Node,
        var_names: &[String],
        source: &str,
    ) -> bool {
        if cond.kind() != "binary_expression" {
            return false;
        }
        let op = ast_utils::get_binary_operator(cond, source).unwrap_or_default();
        if op != "!=" && op != "==" {
            return false;
        }

        let (left, right) = match (
            cond.child_by_field_name("left"),
            cond.child_by_field_name("right"),
        ) {
            (Some(l), Some(r)) => (l, r),
            _ => return false,
        };

        // One side should be 0/0u, the other should be (expr >> var)
        let (shift_side, zero_side) = if self.is_zero_literal(&right, source) {
            (left, right)
        } else if self.is_zero_literal(&left, source) {
            (right, left)
        } else {
            return false;
        };
        let _ = zero_side; // used only for selection above

        // shift_side should be a right-shift containing one of our variables
        let shift_expr = if shift_side.kind() == "parenthesized_expression" {
            shift_side.named_child(0).unwrap_or(shift_side)
        } else {
            shift_side
        };

        if shift_expr.kind() == "binary_expression" {
            if let Some(shift_op) = ast_utils::get_binary_operator(&shift_expr, source) {
                if shift_op == ">>" {
                    if let Some(rhs) = shift_expr.child_by_field_name("right") {
                        let rhs_text = ast_utils::get_node_text(&rhs, source);
                        if var_names.iter().any(|v| v == rhs_text) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    fn is_zero_literal(&self, node: &Node, source: &str) -> bool {
        let text = ast_utils::get_node_text(node, source).trim().to_string();
        text == "0" || text == "0u" || text == "0U" || text == "0L" || text == "0UL"
    }

    /// Check if there's a validation check in the scope before the shift
    fn has_validation_check(
        &self,
        scope: &Node,
        var_name: &str,
        source: &str,
        shift_node: &Node,
    ) -> bool {
        let shift_line = shift_node.start_position().row;

        for i in 0..scope.named_child_count() {
            if let Some(child) = scope.named_child(i) {
                let child_line = child.start_position().row;

                // Only check statements before the shift
                if child_line >= shift_line {
                    break;
                }

                if child.kind() == "if_statement" {
                    if let Some(condition) = child.child_by_field_name("condition") {
                        if self.checks_shift_bounds(&condition, var_name, source) {
                            // Check if the consequence has return/exit
                            if let Some(consequence) = child.child_by_field_name("consequence") {
                                if Self::has_return_or_error_handling(&consequence, source) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Check if a condition validates shift bounds
    fn checks_shift_bounds(&self, condition: &Node, var_name: &str, source: &str) -> bool {
        let condition_text = ast_utils::get_node_text(condition, source);

        // Look for patterns like:
        // - var < 0
        // - var < PRECISION(...)
        // - var >= PRECISION(...)
        // - var >= 32
        // - var < 32
        // - var < sizeof(type) * CHAR_BIT

        // Check for negative validation
        let has_negative_check = condition_text.contains(&format!("{} < 0", var_name))
            || condition_text.contains(&format!("0 > {}", var_name))
            || condition_text.contains(&format!("{} >= 0", var_name))
            || condition_text.contains(&format!("0 <= {}", var_name));

        // Check for width/precision validation
        let has_width_check = condition_text.contains(&format!("{} <", var_name))
            || condition_text.contains(&format!("{} >=", var_name))
            || condition_text.contains("PRECISION")
            || condition_text.contains("CHAR_BIT")
            || condition_text.contains("_MAX");

        // For thorough validation, we need both checks (or a combined check)
        // But we'll accept either for now to avoid false positives
        if has_negative_check || has_width_check {
            return true;
        }

        // Also check child binary expressions more carefully
        for i in 0..condition.child_count() {
            if let Some(child) = condition.child(i) {
                if child.kind() == "binary_expression" {
                    if let Some(operator) = ast_utils::get_binary_operator(&child, source) {
                        if operator == "<"
                            || operator == ">"
                            || operator == "<="
                            || operator == ">="
                        {
                            let left = child.child_by_field_name("left");
                            let right = child.child_by_field_name("right");

                            if let (Some(l), Some(r)) = (left, right) {
                                let left_text = ast_utils::get_node_text(&l, source);
                                let right_text = ast_utils::get_node_text(&r, source);

                                // Check if this compares our variable with bounds
                                if left_text == var_name || right_text == var_name {
                                    // Check for width-related constants or expressions
                                    if right_text.contains("PRECISION")
                                        || right_text.contains("CHAR_BIT")
                                        || right_text.contains("MAX")
                                        || left_text.contains("PRECISION")
                                        || left_text.contains("CHAR_BIT")
                                        || left_text.contains("MAX")
                                        || right_text == "0"
                                        || left_text == "0"
                                    {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Check if branch contains return or error handling
    fn has_return_or_error_handling(node: &Node, source: &str) -> bool {
        let text = ast_utils::get_node_text(node, source);

        if text.contains("return") || text.contains("error") || text.contains("exit") {
            return true;
        }

        // Check for return/exit statements in any child subtree
        let mut cursor = node.walk();
        let children: Vec<Node> = node.children(&mut cursor).collect();
        children.iter().any(|child| {
            query::find_first_descendant(*child, |n| {
                matches!(
                    n.kind(),
                    "return_statement" | "break_statement" | "continue_statement"
                )
            })
            .is_some()
        })
    }

    /// Check if shift operation is in a safe branch
    fn is_in_safe_branch(&self, if_node: &Node, shift_node: &Node) -> bool {
        // Check if shift_node is in the consequence or alternative
        if let Some(consequence) = if_node.child_by_field_name("consequence") {
            if Self::is_descendant(&consequence, shift_node) {
                return true;
            }
        }

        if let Some(alternative) = if_node.child_by_field_name("alternative") {
            if Self::is_descendant(&alternative, shift_node) {
                return true;
            }
        }

        false
    }

    /// Walk up to enclosing if_statement ancestors and extract variable
    /// bounds from their conditions. Only applies when the node is inside
    /// the consequence (then-branch) of the if.
    fn extract_if_condition_ranges(
        node: &Node,
        source: &str,
        macros: &MacroConstantMap,
        ranges: &mut VarRangeMap,
    ) {
        let mut current = node.parent();
        while let Some(ancestor) = current {
            if ancestor.kind() == "if_statement" {
                // Only apply bounds if node is in the consequence (then-branch)
                if let Some(consequence) = ancestor.child_by_field_name("consequence") {
                    if node.start_byte() >= consequence.start_byte()
                        && node.end_byte() <= consequence.end_byte()
                    {
                        if let Some(condition) = ancestor.child_by_field_name("condition") {
                            let cond = if condition.kind() == "parenthesized_expression" {
                                condition.child(1)
                            } else {
                                Some(condition)
                            };
                            if let Some(cond) = cond {
                                Self::extract_comparison_bounds(&cond, source, macros, ranges);
                            }
                        }
                    }
                }
            }
            current = ancestor.parent();
        }
    }

    /// Extract variable bounds from comparison expressions.
    /// Handles <, <=, >, >=, != operators and compound && conditions.
    fn extract_comparison_bounds(
        node: &Node,
        source: &str,
        macros: &MacroConstantMap,
        ranges: &mut VarRangeMap,
    ) {
        if node.kind() != "binary_expression" {
            return;
        }
        let op = match ast_utils::get_binary_operator(node, source) {
            Some(o) => o,
            None => return,
        };

        // Handle compound && conditions
        if op == "&&" {
            if let Some(left) = node.child_by_field_name("left") {
                Self::extract_comparison_bounds(&left, source, macros, ranges);
            }
            if let Some(right) = node.child_by_field_name("right") {
                Self::extract_comparison_bounds(&right, source, macros, ranges);
            }
            return;
        }

        let (left, right) = match (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            (Some(l), Some(r)) => (l, r),
            _ => return,
        };

        match op {
            "<" => {
                // left < right → left ∈ [_, right-1]
                if left.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&right, source, macros) {
                        let name = ast_utils::get_node_text(&left, source).to_string();
                        let entry = ranges
                            .entry(name)
                            .or_insert(const_eval::ValueRange::new(i64::MIN, i64::MAX));
                        entry.max = entry.max.min(bound - 1);
                    }
                }
                // left < right → right ∈ [left+1, _]
                if right.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&left, source, macros) {
                        let name = ast_utils::get_node_text(&right, source).to_string();
                        let entry = ranges
                            .entry(name)
                            .or_insert(const_eval::ValueRange::new(i64::MIN, i64::MAX));
                        entry.min = entry.min.max(bound + 1);
                    }
                }
            }
            "<=" => {
                if left.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&right, source, macros) {
                        let name = ast_utils::get_node_text(&left, source).to_string();
                        let entry = ranges
                            .entry(name)
                            .or_insert(const_eval::ValueRange::new(i64::MIN, i64::MAX));
                        entry.max = entry.max.min(bound);
                    }
                }
                if right.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&left, source, macros) {
                        let name = ast_utils::get_node_text(&right, source).to_string();
                        let entry = ranges
                            .entry(name)
                            .or_insert(const_eval::ValueRange::new(i64::MIN, i64::MAX));
                        entry.min = entry.min.max(bound);
                    }
                }
            }
            ">" => {
                // left > right → left ∈ [right+1, _]
                if left.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&right, source, macros) {
                        let name = ast_utils::get_node_text(&left, source).to_string();
                        let entry = ranges
                            .entry(name)
                            .or_insert(const_eval::ValueRange::new(i64::MIN, i64::MAX));
                        entry.min = entry.min.max(bound + 1);
                    }
                }
                if right.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&left, source, macros) {
                        let name = ast_utils::get_node_text(&right, source).to_string();
                        let entry = ranges
                            .entry(name)
                            .or_insert(const_eval::ValueRange::new(i64::MIN, i64::MAX));
                        entry.max = entry.max.min(bound - 1);
                    }
                }
            }
            ">=" => {
                if left.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&right, source, macros) {
                        let name = ast_utils::get_node_text(&left, source).to_string();
                        let entry = ranges
                            .entry(name)
                            .or_insert(const_eval::ValueRange::new(i64::MIN, i64::MAX));
                        entry.min = entry.min.max(bound);
                    }
                }
                if right.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&left, source, macros) {
                        let name = ast_utils::get_node_text(&right, source).to_string();
                        let entry = ranges
                            .entry(name)
                            .or_insert(const_eval::ValueRange::new(i64::MIN, i64::MAX));
                        entry.max = entry.max.min(bound);
                    }
                }
            }
            "!=" => {
                // x != 0 doesn't give a tight range for shifts, skip
            }
            _ => {}
        }
    }

    /// Check if target is a descendant of node
    fn is_descendant(node: &Node, target: &Node) -> bool {
        query::find_first_descendant(*node, |n| n.id() == target.id()).is_some()
    }

    /// True when the shift amount is provably in range once the project's
    /// function-like macros are expanded and the locals it names are resolved
    /// to their last assignment.
    ///
    /// The two go together on purpose. `field = IDR1_NUMPAGENDXB_VAL(reg &
    /// IDR1_NUMPAGENDXB); ... 1 << (field + 1)` needs both hops: without the
    /// expansion the initialiser is an opaque call, and without the local
    /// resolution the bound the expansion proves never reaches the shift.
    ///
    /// Identifiers are seeded rather than resolved inside the evaluator so
    /// that a name already bounded by an enclosing loop or `if` keeps that
    /// (tighter, control-flow-aware) bound.
    fn shift_amount_bounded_after_expansion(
        &self,
        shift_node: &Node,
        amount: &Node,
        source: &str,
        width: i64,
    ) -> bool {
        let fmacros = self.current_function_macros.borrow();
        let macros = self.current_macros.borrow();

        let mut var_ranges = const_eval::extract_loop_var_ranges(shift_node, source, &macros);
        Self::extract_if_condition_ranges(shift_node, source, &macros, &mut var_ranges);

        let mut names: Vec<String> = query::find_descendants_of_kind(*amount, "identifier")
            .iter()
            .map(|id| ast_utils::get_node_text(id, source).to_string())
            .collect();
        if amount.kind() == "identifier" {
            names.push(ast_utils::get_node_text(amount, source).to_string());
        }
        let resolved: Vec<(String, const_eval::ValueRange)> = names
            .into_iter()
            .filter(|name| !var_ranges.contains_key(name))
            .filter_map(|name| {
                let range = const_eval::resolve_local_var_range_expanding(
                    &name,
                    shift_node,
                    source,
                    &macros,
                    &var_ranges,
                    &fmacros,
                )?;
                Some((name, range))
            })
            .collect();
        var_ranges.extend(resolved);

        const_eval::try_evaluate_range_expanding(amount, source, &macros, &var_ranges, &fmacros)
            .is_some_and(|range| Self::range_within_width(&range, width))
    }

    /// Evaluate the shift amount's range using CFG-based VRA.
    fn eval_shift_range_via_vra(
        &self,
        shift_node: &Node,
        right_node: &Node,
        source: &str,
    ) -> Option<const_eval::ValueRange> {
        let vra_results = self.vra_results.borrow();
        let cfgs = self.function_cfgs.borrow();
        let macros = self.current_macros.borrow();

        if vra_results.is_empty() || cfgs.is_empty() {
            return None;
        }

        let func = ast_utils::find_containing_function(shift_node)?;
        let start_byte = func.start_byte();
        let cfg = cfgs.get(&start_byte)?;
        let vra = vra_results.get(&start_byte)?;
        let body = func.child_by_field_name("body")?;

        value_range::eval_expr_range_at(vra, cfg, &body, source, &macros, right_node)
    }
}
