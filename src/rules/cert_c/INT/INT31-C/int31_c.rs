// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! INT31-C: Ensure that integer conversions do not result in lost or misinterpreted data
//!
//! This rule detects integer conversions that may result in lost or misinterpreted data:
//! - Signed to unsigned conversion without checking for negative values
//! - Unsigned to signed conversion without checking for overflow
//! - Narrowing conversions without bounds checking
//! - memset with value > UCHAR_MAX
//! - time_t comparison with -1 without proper cast

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::{self, FunctionCfg};
use crate::analyze::const_eval::{self, MacroConstantMap};
use crate::analyze::context::SummaryLookup;
use crate::analyze::context::{ProjectContext, ScopedTable};
use crate::analyze::function_summary::{self, FunctionSummary};
use crate::analyze::value_range::RangeAnalysisResult;
use crate::analyze::vra_access;
use crate::manifest::Severity;
use crate::rules::cert_c::int_provenance;
use crate::settings::{AnalysisSettings, IntFacts};
use crate::utility::cert_c::ast_utils::{self, get_node_text, is_function_parameter};
use crate::utility::cert_c::data_model::IntWidth;
use crate::utility::cert_c::data_model::Rank;
use crate::utility::cert_c::declarator_utils;
use crate::utility::cert_c::expr_type::{self, CType, Sign};
use crate::utility::cert_c::guard_dominance;
use crate::utility::cert_c::std_functions;
use lang_parsing_substrate::query;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

pub struct Int31C {
    /// Project-wide `#define` constants, for the value-based truncation
    /// channel; the other INT rules already carry these.
    project_macros: RefCell<Arc<MacroConstantMap>>,
    /// `project_macros` merged with the current file's own defines (file wins).
    current_macros: RefCell<MacroConstantMap>,
    function_cfgs: RefCell<Arc<HashMap<usize, FunctionCfg>>>,
    vra_results: RefCell<Arc<HashMap<usize, RangeAnalysisResult>>>,
    function_summaries: RefCell<ScopedTable<FunctionSummary>>,
    /// Reverse call graph: callee_name → set of caller names.
    callers: RefCell<Arc<HashMap<String, HashSet<String>>>>,
    /// Globals written by a tainted function — see the INT32-C provenance gate.
    global_writers: RefCell<Arc<HashMap<String, HashSet<String>>>>,
    /// Per-function memo of risky variable names, keyed by function node id;
    /// cleared per file.
    risky_vars_cache: RefCell<HashMap<usize, HashSet<String>>>,
    /// Per-function memo of parameter names, keyed by function node id; cleared
    /// per file alongside `risky_vars_cache`.
    param_names_cache: RefCell<HashMap<usize, Vec<String>>>,
    /// Cross-file typedef alias map, reached through the shared
    /// [`overflow_helpers::resolve_typedef_chain`] before every
    /// `get_type_width` lookup so a `typedef double real_t;` (an earlier fix
    /// left this uncovered) or a `sqlite3_int64` chain to
    /// `long long int` (an earlier fix sample) resolves to a known width
    /// instead of falling through as `None` (third consumer
    /// of an earlier fix's shared resolver).
    typedef_types: RefCell<Arc<HashMap<String, String>>>,
    /// The integer data model the settings credit: how wide each side of a
    /// conversion is, or may be.
    data_model: Cell<IntFacts>,
}

impl Int31C {
    pub fn new() -> Self {
        Self {
            project_macros: RefCell::new(Arc::new(MacroConstantMap::new())),
            current_macros: RefCell::new(MacroConstantMap::new()),
            function_cfgs: RefCell::new(Arc::default()),
            vra_results: RefCell::new(Arc::default()),
            function_summaries: RefCell::default(),
            callers: RefCell::default(),
            global_writers: RefCell::new(Arc::new(HashMap::new())),
            risky_vars_cache: RefCell::new(HashMap::new()),
            param_names_cache: RefCell::new(HashMap::new()),
            typedef_types: RefCell::new(Arc::new(HashMap::new())),
            data_model: Cell::new(IntFacts::default()),
        }
    }

    /// [`get_type_width`] with a typedef-chain pre-resolve. Tries the
    /// direct spelling first (fast path, no map lookup), and on a miss
    /// walks the cross-file typedef chain to a terminal builtin and
    /// tries again -- so `typedef double real_t;` or a
    /// `sqlite3_int64 -> long long int` chain lands on the same width
    /// row an unaliased spelling would.
    fn get_type_width_resolved(&self, type_str: &str) -> Option<IntWidth> {
        let model = self.data_model.get();
        if let Some(w) = get_type_width(type_str, model) {
            return Some(w);
        }
        let typedefs = self.typedef_types.borrow();
        if typedefs.is_empty() {
            return None;
        }
        let resolved =
            crate::utility::cert_c::overflow_helpers::resolve_typedef_chain(type_str, &typedefs);
        if resolved == type_str {
            return None;
        }
        get_type_width(&resolved, model)
    }

    /// Opt-in provenance gate for lossy conversions: returns true when the
    /// converted value `operand` derives from untrusted or unbounded input (a
    /// taint source, a full-range parser, an untrusted-decode accessor, a
    /// tainted-summary callee return, or a tainted global). When false, the
    /// value is bounded local state and the conversion is treated as safe —
    /// the same opt-in philosophy as INT30-C/INT32-C, applied to the converted
    /// operand. Runs in every configuration; without cross-file context the
    /// project-local summary channels simply find nothing to match.
    fn converted_value_is_risky(&self, operand: &Node, source: &str) -> bool {
        let summaries = self.function_summaries.borrow();
        let func = match ast_utils::find_containing_function(operand) {
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

        int_provenance::operand_is_risky(
            operand,
            risky_vars,
            &summaries,
            &global_writers,
            param_ctx.as_ref(),
            source,
        )
    }

    /// Whether the value of `source_expr_node` just before `node` provably
    /// fits a target of `target_width` bits and the given signedness: its
    /// range from value-range analysis, which follows each guard the path
    /// to `node` passes and its polarity, with this file's macros. A
    /// constant expression (`v & 0xFF`) has its range with no analysis at
    /// all.
    fn vra_proves_conversion_safe(
        &self,
        node: &Node,
        source_expr_node: &Node,
        source: &str,
        target_type: &str,
        target_width: u32,
        target_signed: bool,
    ) -> bool {
        let char_signed = self.plain_char_signedness(target_type);
        let macros = self.current_macros.borrow();
        let var_ranges = vra_access::var_ranges_replay_at(
            &self.function_cfgs.borrow(),
            &self.vra_results.borrow(),
            node,
            source,
            &macros,
        )
        .unwrap_or_default();
        let range = const_eval::try_evaluate_range(source_expr_node, source, &macros, &var_ranges)
            .or_else(|| {
                var_ranges
                    .get(get_node_text(source_expr_node, source).trim())
                    .copied()
            });
        range.is_some_and(|range| match char_signed {
            // A plain `char` the project has not declared either way keeps
            // only a value that fits it whichever way the build has it.
            Some(None) => {
                range.fits_in_signed(target_width) && range.fits_in_unsigned(target_width)
            }
            Some(Some(signed)) if signed => range.fits_in_signed(target_width),
            Some(Some(_)) => range.fits_in_unsigned(target_width),
            None if target_signed => range.fits_in_signed(target_width),
            None => range.fits_in_unsigned(target_width),
        })
    }

    /// For a plain `char` target, whether the project declares it signed
    /// (`None` when it does not say). `None` for any other type.
    fn plain_char_signedness(&self, target_type: &str) -> Option<Option<bool>> {
        (target_type.trim() == "char").then(|| self.data_model.get().char_signed())
    }

    /// Value-based definite-truncation channel — the conversion analogue of
    /// the `expression_overflows_*_vra` channels INT30-C and INT32-C run ahead
    /// of their provenance gates.
    ///
    /// Returns true only when VRA gives the converted expression a known range
    /// and *every* value in it fails to fit the target type, so the conversion
    /// provably loses data (`1000` into `uint8_t`, `LONG_MAX` into
    /// `signed char`). A range that merely straddles the target band is a
    /// possible, not definite, truncation and returns false, leaving the
    /// provenance gate to decide — the same "definite" contract, so bounded
    /// local values stay suppressed.
    fn conversion_definitely_truncates(
        &self,
        node: &Node,
        source_expr_node: &Node,
        source: &str,
        target_width: u32,
        target_signed: bool,
    ) -> bool {
        if target_width == 0 || target_width > 63 {
            return false;
        }
        // Intra-block forward simulation, not block-entry state: `uint16_t
        // wide = 1000; uint8_t narrow = wide;` puts both statements in one
        // basic block, so the entry state this rule's suppression path uses
        // has no value for `wide` at all. Detection needs the stronger view;
        // the suppression path is deliberately left on entry semantics so this
        // does not silently change what INT31-C suppresses.
        let macros = self.current_macros.borrow();
        let var_ranges = match vra_access::var_ranges_replay_at(
            &self.function_cfgs.borrow(),
            &self.vra_results.borrow(),
            node,
            source,
            &macros,
        ) {
            Some(r) => r,
            None => return false,
        };
        let range = const_eval::try_evaluate_range(source_expr_node, source, &macros, &var_ranges)
            .or_else(|| {
                var_ranges
                    .get(get_node_text(source_expr_node, source).trim())
                    .copied()
            });
        let range = match range {
            Some(r) => r,
            None => return false,
        };
        if target_signed {
            let target_max = (1i64 << (target_width - 1)) - 1;
            let target_min = -(1i64 << (target_width - 1));
            range.min > target_max || range.max < target_min
        } else {
            let target_max = (1i64 << target_width) - 1;
            range.min > target_max || range.max < 0
        }
    }

    /// Heuristic: is the value of `var_name` in the enclosing function
    /// provably free of any externally-controlled input path?
    ///
    /// A "taint-free" value within a bounded block (`if (var < LIT)`) is
    /// overwhelmingly non-negative in practice, because programs rarely
    /// pair a fixed-source positive literal with a `< LIMIT` guard unless
    /// they mean the value to be a size. Returns true only when:
    /// - the containing function's summary has no taint-source call, AND
    /// - every `var = someFn(...)` assignment in the body targets a callee
    ///   whose summary is also taint-free, AND
    /// - when `var` is a parameter, every caller is taint-free too.
    ///
    /// If any callee, caller, or summary lookup is missing, the check
    /// conservatively returns false (preserving the flag).
    fn var_is_taint_free(&self, node: &Node, var_name: &str, source: &str) -> bool {
        let func = match ast_utils::find_containing_function(node) {
            Some(f) => f,
            None => return false,
        };

        let func_name = match cfg::get_function_name(&func, source) {
            Some(n) => n,
            None => return false,
        };

        let summaries = self.function_summaries.borrow();
        if summaries.is_empty() {
            // No cross-file context — don't second-guess the rule's
            // existing VRA/guard checks.
            return false;
        }

        let func_summary = match summaries.get(func_name) {
            Some(s) => s,
            None => return false,
        };
        if func_summary.has_env03_taint_source {
            return false;
        }

        let body = match func.child_by_field_name("body") {
            Some(b) => b,
            None => return false,
        };

        if body_has_tainted_call_assignment_to(&body, var_name, &summaries, source) {
            return false;
        }

        if is_function_parameter(&func, var_name, source) {
            // Parameter case: judged by what every caller passes at this
            // position, as the caller's own body would judge it, over a
            // closed caller set (ADR-0011; `int_provenance::parameter_is_risky`).
            let params = function_summary::collect_param_names(&func, source);
            let Some(idx) = params.iter().position(|p| p == var_name) else {
                return false;
            };
            return !int_provenance::parameter_is_risky(
                func_name,
                idx,
                &*summaries,
                &self.global_writers.borrow(),
            );
        }

        // Local variable: only suppress when we see a call-return assignment
        // from at least one clean callee. Without such evidence the var may
        // have been sourced from a file-scope global, an address-of read,
        // or another channel we can't inspect — stay conservative.
        body_has_any_call_assignment_to(&body, var_name, source)
    }
}

/// Walk `body` looking for any assignment or initializer that stores a
/// call-expression result into `var_name`. If the callee's summary has
/// a taint source, the assignment is tainted — return true.
fn body_has_tainted_call_assignment_to(
    body: &Node,
    var_name: &str,
    summaries: &(impl SummaryLookup + ?Sized),
    source: &str,
) -> bool {
    query::find_first_descendant(*body, |node| match node.kind() {
        "assignment_expression" => {
            if let Some(lhs) = node.child_by_field_name("left") {
                let lhs_text = get_node_text(&lhs, source).trim();
                if lhs_text == var_name {
                    if let Some(rhs) = node.child_by_field_name("right") {
                        return call_rhs_has_taint_source(&rhs, summaries, source);
                    }
                }
            }
            false
        }
        "init_declarator" => {
            if let Some(decl) = node.child_by_field_name("declarator") {
                if declarator_name_matches(&decl, var_name, source) {
                    if let Some(value) = node.child_by_field_name("value") {
                        return call_rhs_has_taint_source(&value, summaries, source);
                    }
                }
            }
            false
        }
        _ => false,
    })
    .is_some()
}

/// Returns true when the identifier embedded in a declarator (handling
/// pointer/array wrappers) exactly equals `var_name`.
fn declarator_name_matches(decl: &Node, var_name: &str, source: &str) -> bool {
    let mut current = *decl;
    loop {
        match current.kind() {
            "identifier" | "field_identifier" => {
                return get_node_text(&current, source).trim() == var_name;
            }
            _ => {
                if let Some(inner) = current.child_by_field_name("declarator") {
                    current = inner;
                    continue;
                }
                // Try first named child as fallback
                let mut next = None;
                for i in 0..current.child_count() {
                    if let Some(c) = current.child(i) {
                        if c.is_named() {
                            next = Some(c);
                            break;
                        }
                    }
                }
                match next {
                    Some(n) => current = n,
                    None => return false,
                }
            }
        }
    }
}

/// Walk `body` looking for any assignment or initializer that stores a
/// call-expression result into `var_name`. Returns true if at least one
/// such `var = fn(...)` exists, regardless of the callee's taint status.
fn body_has_any_call_assignment_to(body: &Node, var_name: &str, source: &str) -> bool {
    query::find_first_descendant(*body, |node| match node.kind() {
        "assignment_expression" => {
            if let Some(lhs) = node.child_by_field_name("left") {
                if get_node_text(&lhs, source).trim() == var_name {
                    if let Some(rhs) = node.child_by_field_name("right") {
                        return unwrap_to_call(rhs).kind() == "call_expression";
                    }
                }
            }
            false
        }
        "init_declarator" => {
            if let Some(decl) = node.child_by_field_name("declarator") {
                if declarator_name_matches(&decl, var_name, source) {
                    if let Some(value) = node.child_by_field_name("value") {
                        return unwrap_to_call(value).kind() == "call_expression";
                    }
                }
            }
            false
        }
        _ => false,
    })
    .is_some()
}

/// Returns true if `rhs` is (or contains at the top level) a call whose
/// callee's summary reports a taint source.
fn call_rhs_has_taint_source(
    rhs: &Node,
    summaries: &(impl SummaryLookup + ?Sized),
    source: &str,
) -> bool {
    let call = unwrap_to_call(*rhs);
    if call.kind() != "call_expression" {
        return false;
    }
    let func = match call.child_by_field_name("function") {
        Some(f) => f,
        None => return false,
    };
    let name = get_node_text(&func, source);
    let ident = name
        .rsplit(|c: char| !c.is_alphanumeric() && c != '_')
        .next()
        .unwrap_or(name);
    match summaries.get(ident) {
        // A helper that transitively returns taint (`return recv_wrapper()`)
        // is flagged via `returns_tainted` even when its own body contains
        // no direct taint source.
        Some(s) => s.has_env03_taint_source || s.returns_tainted,
        None => false,
    }
}

fn unwrap_to_call(mut node: Node) -> Node {
    loop {
        match node.kind() {
            "parenthesized_expression" => {
                if let Some(inner) = node.named_child(0) {
                    node = inner;
                    continue;
                }
                break;
            }
            "cast_expression" => {
                if let Some(value) = node.child_by_field_name("value") {
                    node = value;
                    continue;
                }
                break;
            }
            _ => break,
        }
    }
    node
}

/// Returns true when `node` sits inside an `if (ident < N)` / `if (ident <= N)`
/// guard where `N` is a non-negative integer literal (or `ident > -1` style).
/// Looks up through 15 ancestors for the enclosing `if_statement`.
fn is_inside_upper_bound_guard(node: &Node, source: &str, ident: &str) -> bool {
    if ident.is_empty() {
        return false;
    }
    let mut current = *node;
    for _ in 0..15 {
        let parent = match current.parent() {
            Some(p) => p,
            None => break,
        };
        if parent.kind() == "if_statement" {
            if let Some(condition) = parent.child_by_field_name("condition") {
                let cond_text = get_node_text(&condition, source);
                if condition_is_upper_bound_on(cond_text, ident) {
                    return true;
                }
            }
        }
        current = parent;
    }
    false
}

fn condition_is_upper_bound_on(cond: &str, ident: &str) -> bool {
    // Strip parens and whitespace for simpler matching.
    let trimmed = cond.replace([' ', '\t', '\n', '('], "").replace(')', "");
    // Patterns that establish an upper bound on `ident`:
    // - ident<N, ident<=N with N a non-negative literal
    // - N>ident, N>=ident (flipped)
    for op in ["<=", "<"] {
        let needle = format!("{}{}", ident, op);
        if let Some(idx) = trimmed.find(&needle) {
            let rest = &trimmed[idx + needle.len()..];
            if let Some(n) = leading_integer(rest) {
                if n >= 0 {
                    return true;
                }
            }
        }
    }
    for op in [">=", ">"] {
        let needle = format!("{}{}", op, ident);
        if let Some(idx) = trimmed.find(&needle) {
            let before = &trimmed[..idx];
            if let Some(n) = trailing_integer(before) {
                if n >= 0 {
                    return true;
                }
            }
        }
    }
    false
}

fn leading_integer(s: &str) -> Option<i64> {
    let mut end = 0;
    let bytes = s.as_bytes();
    if bytes.first() == Some(&b'-') {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || (end == 1 && bytes[0] == b'-') {
        return None;
    }
    s[..end].parse().ok()
}

fn trailing_integer(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    let mut start = bytes.len();
    while start > 0 && bytes[start - 1].is_ascii_digit() {
        start -= 1;
    }
    if start > 0 && bytes[start - 1] == b'-' {
        start -= 1;
    }
    if start == bytes.len() {
        return None;
    }
    s[start..].parse().ok()
}

/// Returns the bit-width of a known integer type, or None for unknown types.
///
/// The integer table itself is [`ast_utils::integer_type_width`] (shared since
/// an earlier fix, which needed the same widths in API00-C); what stays here is the
/// floating-type branch, which is an INT31-C convention rather than a width.
fn get_type_width(type_str: &str, model: IntFacts) -> Option<IntWidth> {
    if let Some(width) = ast_utils::integer_type_width(type_str, model) {
        return Some(width);
    }

    // Floating types: not an integer bit-width at all, but any conversion to
    // an integer type risks losing the fractional part (and, unlike a
    // same-or-wider integer-to-integer move, that loss happens regardless of
    // the target's width — a `long` is exactly as unable to hold a fraction
    // as a `char` is). FLOAT_AS_INTEGER_WIDTH is deliberately wider than every
    // recognized integer width above so the caller's plain numeric comparison
    // (`rhs_width > lhs_width` ⇒ narrowing) treats float/double/long double as
    // narrowing into ANY integer LHS, while still comparing equal against each
    // other so a float<->double<->long double move is left to FLP34-C, which
    // owns floating-to-floating precision loss.
    let t = type_str.trim();
    if t == "float" || t == "double" || t == "long double" {
        return Some(IntWidth {
            rank: None,
            min: FLOAT_AS_INTEGER_WIDTH,
            max: Some(FLOAT_AS_INTEGER_WIDTH),
        });
    }

    None
}

/// Whether a value of width `from` may not fit a target of width `to`: an
/// integer target is narrower than any floating value, a floating target
/// never narrower than an integer (a fraction or precision, not bits, is what
/// it can lose, and FLP34-C owns floating-to-floating), and two integers
/// compare as the data model allows ([`IntWidth::may_be_narrower_than`]).
fn may_be_narrower(to: IntWidth, from: IntWidth) -> bool {
    let is_float = |w: IntWidth| w.min == FLOAT_AS_INTEGER_WIDTH;
    match (is_float(to), is_float(from)) {
        (true, _) => false,
        (false, true) => true,
        (false, false) => to.may_be_narrower_than(from),
    }
}

/// See [`get_type_width`]'s floating-type branch.
const FLOAT_AS_INTEGER_WIDTH: u32 = 65;

/// Signed integer aliases, matched by their whole name.
const SIGNED_ALIASES: &[&str] = &[
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "int_least8_t",
    "int_least16_t",
    "int_least32_t",
    "int_least64_t",
    "int_fast8_t",
    "int_fast16_t",
    "int_fast32_t",
    "int_fast64_t",
    "intptr_t",
    "intmax_t",
    "ssize_t",
    "ptrdiff_t",
    "__int8",
    "__int16",
    "__int32",
    "__int64",
    // The Win32 SDK's signed integer typedef names.
    "INT",
    "LONG",
    "SHORT",
    "INT8",
    "INT16",
    "INT32",
    "INT64",
    "LONGLONG",
    "LONG_PTR",
    "INT_PTR",
    "SSIZE_T",
];

/// Unsigned integer aliases, matched by their whole name (the Win32 SDK's
/// are [`ast_utils::is_win32_unsigned_typedef`]'s).
const UNSIGNED_ALIASES: &[&str] = &[
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "uint_least8_t",
    "uint_least16_t",
    "uint_least32_t",
    "uint_least64_t",
    "uint_fast8_t",
    "uint_fast16_t",
    "uint_fast32_t",
    "uint_fast64_t",
    "uintptr_t",
    "uintmax_t",
    "size_t",
];

/// The words of a type spelling that say what type it is: without
/// qualifiers, storage classes or parentheses.
fn type_core(type_str: &str) -> String {
    type_str
        .replace(['(', ')'], " ")
        .split_whitespace()
        .filter(|w| {
            !matches!(
                *w,
                "const"
                    | "volatile"
                    | "restrict"
                    | "__restrict"
                    | "__restrict__"
                    | "static"
                    | "extern"
                    | "register"
                    | "auto"
                    | "inline"
                    | "__inline"
                    | "__inline__"
                    | "__extension__"
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The signedness a type spelling states by itself: `Some(true)` for a
/// signed integer type, `Some(false)` for an unsigned one, `None` for plain
/// `char`, a pointer, a non-integer, or a name that is not a known alias.
fn spelled_signedness(type_str: &str) -> Option<bool> {
    let core = type_core(type_str);
    if core.is_empty() || core.contains(['*', '[']) {
        return None;
    }
    let words: Vec<&str> = core.split_whitespace().collect();
    if words.contains(&"unsigned") {
        return Some(false);
    }
    let integer_word = |w: &&str| matches!(*w, "signed" | "int" | "short" | "long");
    if words.contains(&"signed") && words.iter().all(|w| integer_word(w) || *w == "char") {
        return Some(true);
    }
    if words.iter().all(integer_word) {
        return Some(true);
    }
    if SIGNED_ALIASES.contains(&core.as_str()) {
        return Some(true);
    }
    if UNSIGNED_ALIASES.contains(&core.as_str()) || ast_utils::is_win32_unsigned_typedef(&core) {
        return Some(false);
    }
    None
}

// Types ranked by size (smallest to largest) for narrowing detection
const NARROW_TYPES: &[&str] = &["char", "signed char", "unsigned char", "int8_t", "uint8_t"];

const WIDE_TYPES: &[&str] = &[
    // 16-bit types (wider than NARROW_TYPES which are 8-bit)
    "short",
    "unsigned short",
    "short int",
    "unsigned short int",
    "int16_t",
    "uint16_t",
    // 32-bit types
    "int",
    "unsigned",
    "unsigned int",
    "signed int",
    "int32_t",
    "uint32_t",
    // 64-bit types
    "long",
    "unsigned long",
    "long int",
    "unsigned long int",
    "signed long int",
    "long long",
    "unsigned long long",
    "int64_t",
    "uint64_t",
    "size_t",
    // Bare "int64"/"uint64" substring (not just the "_t"-suffixed stdint
    // form) catches project-specific 64-bit typedefs like sqlite3_int64/
    // sqlite3_uint64 and the older sqlite_int64 alias.
    "int64",
    "uint64",
    // Floating types: not narrower/wider than the integer types
    // above in any bit-width sense, but a float/double/long double cast down
    // to a NARROW_TYPES (char-width) target is exactly as lossy as an
    // integer-to-char narrowing, e.g. `(char)some_double_var`. NARROW_TYPES
    // has no floating entries, so this can never fire float-to-float.
    "float",
    "double",
    "long double",
];

impl CertRule for Int31C {
    fn reads_header_facts(&self) -> bool {
        true
    }

    fn rule_id(&self) -> &'static str {
        "INT31-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that integer conversions do not result in lost or misinterpreted data"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "INT31-C"
    }

    fn set_function_cfgs(&self, cfgs: &Arc<HashMap<usize, FunctionCfg>>) {
        *self.function_cfgs.borrow_mut() = Arc::clone(cfgs);
    }

    fn set_vra_results(&self, results: &Arc<HashMap<usize, RangeAnalysisResult>>) {
        *self.vra_results.borrow_mut() = Arc::clone(results);
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_macros.borrow_mut() = context.macro_constants.clone();
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.global_writers.borrow_mut() = context.global_writers.clone();
        *self.typedef_types.borrow_mut() = context.typedef_types.clone();

        *self.callers.borrow_mut() = context.callers.clone();
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        self.data_model.set(settings.facts);
    }

    fn set_visible_types(&self, types: &crate::analyze::context::VisibleTypes) {
        *self.typedef_types.borrow_mut() = types.typedef_types.clone();
    }

    fn needs_vra(&self) -> bool {
        true
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        // Merge project-level macros with this file's own (file wins).
        *self.current_macros.borrow_mut() = const_eval::merged_macro_constants(
            &self.project_macros.borrow(),
            node,
            source,
            self.data_model.get(),
        );
        // Risky-var memo is keyed on tree-sitter node ids, unique only within
        // one parse tree — reset per file.
        self.risky_vars_cache.borrow_mut().clear();
        self.param_names_cache.borrow_mut().clear();
        self.check_function(node, source, &mut violations);
        violations
    }
}

impl Int31C {
    fn check_function(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for function definitions and analyze their bodies
        for func_node in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(body) = func_node.child_by_field_name("body") {
                // Track variable types and validated variables
                let mut var_types: HashMap<String, String> = HashMap::new();

                // First: collect parameter types from function declarator
                if let Some(declarator) = func_node.child_by_field_name("declarator") {
                    self.collect_var_types(&declarator, source, &mut var_types);
                }

                // Then: collect variable types from body
                self.collect_var_types(&body, source, &mut var_types);

                // Second pass: check for unsafe conversions
                self.check_unsafe_conversions(&body, source, violations, &var_types);
            }
        }
    }

    fn collect_var_types(
        &self,
        node: &Node,
        source: &str,
        var_types: &mut HashMap<String, String>,
    ) {
        for n in query::find_descendants_of_kinds(*node, &["declaration", "parameter_declaration"])
        {
            // Collect from declarations
            if n.kind() == "declaration" {
                // Extract type from declaration
                if let Some(type_text) = self.find_type_specifier_text(&n, source) {
                    // Find declarators
                    for i in 0..n.child_count() {
                        if let Some(child) = n.child(i) {
                            if child.kind() == "init_declarator" {
                                if let Some(declarator) = child.child_by_field_name("declarator") {
                                    let var_name = Self::extract_var_name(&declarator, source);
                                    if !var_name.is_empty() {
                                        var_types.insert(
                                            var_name,
                                            Self::qualify_pointer(&type_text, &declarator),
                                        );
                                    }
                                }
                            } else if child.kind() == "identifier" {
                                let var_name = get_node_text(&child, source).to_string();
                                var_types.insert(var_name, type_text.clone());
                            } else if child.kind() == "pointer_declarator" {
                                // A pointer declared without an initializer
                                // (`unsigned char *buf;`) is a direct
                                // `pointer_declarator` child -- neither an
                                // `init_declarator` nor a bare `identifier`.
                                let var_name = Self::extract_var_name(&child, source);
                                if !var_name.is_empty() {
                                    var_types.insert(
                                        var_name,
                                        Self::qualify_pointer(&type_text, &child),
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // Also track from parameter_declarations (function parameters)
            if n.kind() == "parameter_declaration" {
                // For parameters, extract the full type including modifiers
                let type_text = self.extract_parameter_type(&n, source);
                if !type_text.is_empty() {
                    if let Some(declarator) = n.child_by_field_name("declarator") {
                        let var_name = Self::extract_var_name(&declarator, source);
                        if !var_name.is_empty() {
                            var_types
                                .insert(var_name, Self::qualify_pointer(&type_text, &declarator));
                        }
                    }
                }
            }
        }
    }

    /// Spell a pointer-declared variable's type with a trailing `*`.
    ///
    /// The type specifier alone is the *pointee* type: dropping the star
    /// recorded `unsigned char *buf` as `unsigned char`, so `buf += readnb`
    /// (an `ssize_t`) read as a 64-into-8-bit narrowing assignment rather than
    /// a pointer advance. `get_type_width` matches type names
    /// exactly, so a starred type has no integer width at all -- which is
    /// precisely right for a pointer -- and the shared `pointer_typing` engine
    /// reads the same spelling.
    fn qualify_pointer(type_text: &str, declarator: &Node) -> String {
        if declarator_utils::is_pointer_declarator(declarator) {
            format!("{} *", type_text)
        } else {
            type_text.to_string()
        }
    }

    fn find_type_specifier_text(&self, node: &Node, source: &str) -> Option<String> {
        // Collect all type-related parts (handles "signed int", "unsigned long", etc.)
        let mut type_parts = Vec::new();

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let kind = child.kind();
                if kind == "primitive_type"
                    || kind == "type_identifier"
                    || kind == "sized_type_specifier"
                {
                    return Some(get_node_text(&child, source).to_string());
                }
                // Also collect type qualifiers and specifiers
                if kind == "type_qualifier" {
                    let text = get_node_text(&child, source).to_string();
                    if text == "signed" || text == "unsigned" {
                        type_parts.push(text);
                    }
                }
            }
        }

        // If we found qualifiers but no main type specifier, look again for primitive_type
        if !type_parts.is_empty() {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    let kind = child.kind();
                    if kind == "primitive_type" {
                        type_parts.push(get_node_text(&child, source).to_string());
                        return Some(type_parts.join(" "));
                    }
                }
            }
        }

        None
    }

    fn extract_parameter_type(&self, node: &Node, source: &str) -> String {
        // Extract full type from parameter declaration by getting text before declarator
        // For "signed int si", we want "signed int"
        if let Some(declarator) = node.child_by_field_name("declarator") {
            let decl_start = declarator.start_byte();
            let param_start = node.start_byte();
            if decl_start > param_start {
                let type_text = &source[param_start..decl_start];
                return type_text.trim().to_string();
            }
        }
        // Fallback to find_type_specifier_text
        self.find_type_specifier_text(node, source)
            .unwrap_or_default()
    }

    fn extract_var_name(node: &Node, source: &str) -> String {
        if node.kind() == "identifier" {
            return get_node_text(node, source).to_string();
        }
        if node.kind() == "pointer_declarator" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    let name = Self::extract_var_name(&child, source);
                    if !name.is_empty() {
                        return name;
                    }
                }
            }
        }
        String::new()
    }

    fn check_unsafe_conversions(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, String>,
    ) {
        for node in &query::find_descendants_of_kinds(
            *node,
            &[
                "call_expression",
                "binary_expression",
                "cast_expression",
                "assignment_expression",
                "init_declarator",
            ],
        ) {
            // Check for memset with value > UCHAR_MAX and signed→size_t in call args
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_name = get_node_text(&func, source);
                    if func_name == "memset" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            self.check_memset_value(&args, node, source, violations);
                        }
                    }
                }
                self.check_call_argument_conversion(node, source, violations, var_types);
            }

            // Check for time_t comparison with uncast -1
            if node.kind() == "binary_expression" {
                self.check_time_t_comparison(node, source, violations, var_types);
            }

            // Check for cast expressions with potential loss of data
            if node.kind() == "cast_expression" {
                self.check_cast_conversion(node, source, violations, var_types);
            }

            // Check for implicit conversion in assignments
            if node.kind() == "assignment_expression" || node.kind() == "init_declarator" {
                self.check_assignment_conversion(node, source, violations, var_types);
                self.check_narrow_accessor_before_alloc(node, source, violations);
            }
        }
    }

    /// Known accessor functions that return a narrower type than a same-family
    /// sibling exists for -- specifically the sqlite3_value_*/sqlite3_column_*
    /// "int" variants, which return a 32-bit `int` even though the underlying
    /// storage may hold a full 64-bit value, and a `..._int64` sibling exists
    /// for exactly that reason (real example: sqlite
    /// ext/misc/sqlar.c's sqlarUncompressFunc uses `sqlite3_value_int()` on an
    /// attacker-controlled archive-entry size, then passes the truncated
    /// result as an allocation size to `sqlite3_malloc()`).
    fn narrow_accessor_wide_sibling(func_name: &str) -> bool {
        matches!(func_name, "sqlite3_value_int" | "sqlite3_column_int")
    }

    /// True if `var_name` is later passed (textually after `after`, within
    /// `body`) as one of the size-parameter positions of a known allocation
    /// call, using the same dominant-identifier resolution as
    /// `check_call_argument_conversion`.
    fn var_flows_to_alloc_size_arg(
        body: &Node,
        var_name: &str,
        source: &str,
        after: &Node,
    ) -> bool {
        for call in query::find_descendants_of_kind(*body, "call_expression") {
            if call.start_byte() <= after.start_byte() {
                continue;
            }
            let Some(func) = call.child_by_field_name("function") else {
                continue;
            };
            let func_name = get_node_text(&func, source);
            let Some(positions) = Self::get_size_t_param_positions(func_name) else {
                continue;
            };
            let Some(args) = call.child_by_field_name("arguments") else {
                continue;
            };
            let mut arg_nodes = Vec::new();
            for i in 0..args.child_count() {
                if let Some(child) = args.child(i) {
                    if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                        arg_nodes.push(child);
                    }
                }
            }
            for &idx in positions {
                let Some(arg) = arg_nodes.get(idx) else {
                    continue;
                };
                let ident = if arg.kind() == "identifier" {
                    get_node_text(arg, source).to_string()
                } else {
                    Self::extract_dominant_identifier(arg, source)
                };
                if ident == var_name {
                    return true;
                }
            }
        }
        false
    }

    /// Flag `x = sqlite3_value_int(...)` (or `sqlite3_column_int`) when `x`
    /// later flows into an allocation call's size argument -- the 32-bit
    /// accessor truncates a value that may need the full 64-bit range, and a
    /// `..._int64` sibling exists precisely for that case.
    fn check_narrow_accessor_before_alloc(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let (lhs_name, rhs_node) = match node.kind() {
            "assignment_expression" => {
                let left = match node.child_by_field_name("left") {
                    Some(l) => l,
                    None => return,
                };
                if left.kind() != "identifier" {
                    return;
                }
                let right = match node.child_by_field_name("right") {
                    Some(r) => r,
                    None => return,
                };
                (get_node_text(&left, source).trim().to_string(), right)
            }
            "init_declarator" => {
                let declarator = match node.child_by_field_name("declarator") {
                    Some(d) => d,
                    None => return,
                };
                let value = match node.child_by_field_name("value") {
                    Some(v) => v,
                    None => return,
                };
                (Self::extract_var_name(&declarator, source), value)
            }
            _ => return,
        };
        if lhs_name.is_empty() || rhs_node.kind() != "call_expression" {
            return;
        }
        let Some(func) = rhs_node.child_by_field_name("function") else {
            return;
        };
        let func_name = get_node_text(&func, source);
        if !Self::narrow_accessor_wide_sibling(func_name) {
            return;
        }

        let Some(container) = ast_utils::find_containing_function(node) else {
            return;
        };
        let Some(body) = container.child_by_field_name("body") else {
            return;
        };
        if !Self::var_flows_to_alloc_size_arg(&body, &lhs_name, source, node) {
            return;
        }

        // Opt-in provenance gate (mirrors the rest of this rule): only flag
        // when the accessor's own source (the sqlite3_value/column argument)
        // is untrusted/unbounded input.
        if let Some(args) = rhs_node.child_by_field_name("arguments") {
            if let Some(arg0) = args.named_child(0) {
                if !self.converted_value_is_risky(&arg0, source) {
                    return;
                }
            }
        }

        let pos = node.start_position();
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "'{}' from {}() truncated to 32 bits, then used as an allocation size",
                lhs_name, func_name
            ),
            file_path: String::new(),
            line: pos.row + 1,
            column: pos.column + 1,
            suggestion: Some(format!(
                "Use {}64() to preserve the full range before it reaches the allocation size",
                func_name
            )),
            ..Default::default()
        });
    }

    /// Returns the parameter indices that expect size_t for known standard library functions.
    fn get_size_t_param_positions(func_name: &str) -> Option<&'static [usize]> {
        match func_name {
            "malloc" | "sqlite3_malloc" | "sqlite3_malloc64" => Some(&[0]),
            "calloc" => Some(&[0, 1]),
            "realloc" | "sqlite3_realloc" | "sqlite3_realloc64" => Some(&[1]),
            "aligned_alloc" => Some(&[0, 1]),
            "memcpy" | "memmove" | "memset" | "memcmp" => Some(&[2]),
            "strncpy" | "strncat" | "strncmp" => Some(&[2]),
            "snprintf" => Some(&[1]),
            "fread" | "fwrite" => Some(&[1, 2]),
            "strnlen" | "wcsnlen" => Some(&[1]),
            "qsort" | "bsearch" => Some(&[2, 3]),
            _ => None,
        }
    }

    /// Check for implicit signed→unsigned conversion in function call arguments
    /// where the parameter expects size_t. This catches CWE-194 (sign extension)
    /// and CWE-195 (signed to unsigned conversion error).
    fn check_call_argument_conversion(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, String>,
    ) {
        let func = match node.child_by_field_name("function") {
            Some(f) => f,
            None => return,
        };
        let func_name = get_node_text(&func, source).to_string();

        let size_t_positions = match Self::get_size_t_param_positions(&func_name) {
            Some(p) => p,
            None => return,
        };

        let args = match node.child_by_field_name("arguments") {
            Some(a) => a,
            None => return,
        };

        // Collect actual argument nodes (skip parens and commas)
        let mut arg_nodes = Vec::new();
        for i in 0..args.child_count() {
            if let Some(child) = args.child(i) {
                if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                    arg_nodes.push(child);
                }
            }
        }

        for &param_idx in size_t_positions {
            if param_idx >= arg_nodes.len() {
                continue;
            }
            let arg_node = &arg_nodes[param_idx];

            // Skip explicit casts — user has acknowledged the conversion
            if arg_node.kind() == "cast_expression" {
                continue;
            }

            // Skip sizeof expressions — always non-negative
            let arg_text = get_node_text(arg_node, source).to_string();
            if arg_node.kind() == "sizeof_expression" || arg_text.contains("sizeof") {
                continue;
            }

            // Skip non-negative literals
            if arg_node.kind() == "number_literal" {
                continue;
            }

            // Determine the argument's declared type via its dominant identifier
            let ident = if arg_node.kind() == "identifier" {
                arg_text.clone()
            } else {
                Self::extract_dominant_identifier(arg_node, source)
            };
            if ident.is_empty() {
                continue;
            }

            let arg_type = match var_types.get(&ident) {
                Some(t) => t.clone(),
                None => continue,
            };

            // Only flag signed types — unsigned→size_t is fine
            if !self.is_signed_type(&arg_type) {
                continue;
            }

            // VRA suppression: if value is provably non-negative, safe for size_t
            if self.vra_proves_conversion_safe(node, arg_node, source, "size_t", 64, false) {
                continue;
            }
            if self.guards_prove_fit(node, arg_node, source, &arg_type, "size_t") {
                continue;
            }

            // Suppression: cross-function taint-free check. If the value is
            // bounded above (via an `if (ident < LIT)` or equivalent guard)
            // and no taint-source call touches the variable — directly, via
            // call-return assignment, or via a caller when `ident` is a
            // parameter — treat as safe.
            if is_inside_upper_bound_guard(node, source, &ident)
                && self.var_is_taint_free(node, &ident, source)
            {
                continue;
            }

            // Opt-in provenance gate (mirrors INT30-C/INT32-C): only flag when
            // the converted value derives from untrusted/unbounded input. A
            // bounded-local signed value is safe to pass to size_t in practice.
            if !self.converted_value_is_risky(arg_node, source) {
                continue;
            }

            let pos = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Signed value '{}' ({}) implicitly converted to size_t in {}() call",
                    ident, arg_type, func_name
                ),
                file_path: String::new(),
                line: pos.row + 1,
                column: pos.column + 1,
                suggestion: Some(
                    "Validate that the value is non-negative before passing to size_t parameter, or use an explicit cast".to_string(),
                ),
                ..Default::default()
            });
        }
    }

    fn check_memset_value(
        &self,
        args_node: &Node,
        call_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // memset(ptr, value, size) - check if value is > 255
        let mut arg_idx = 0;
        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                    if arg_idx == 1 {
                        // This is the value argument
                        let value_text = get_node_text(&child, source);
                        // Check if it's a literal number > 255
                        if let Ok(value) = value_text.parse::<i64>() {
                            if !(0..=255).contains(&value) {
                                let pos = call_node.start_position();
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::High,
                                    message: format!(
                                        "memset value {} will be truncated to unsigned char (0-255)",
                                        value
                                    ),
                                    file_path: String::new(),
                                    line: pos.row + 1,
                                    column: pos.column + 1,
                                    suggestion: Some(
                                        "Use a value in the range 0-255 for memset".to_string(),
                                    ),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                    arg_idx += 1;
                }
            }
        }
    }

    fn check_time_t_comparison(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, String>,
    ) {
        // Check if comparing time_t with -1 without cast
        let node_text = get_node_text(node, source);

        // Look for pattern: time_t_var != -1 or time_t_var == -1
        if let Some(left) = node.child_by_field_name("left") {
            let left_text = get_node_text(&left, source);

            // Check if left is a time_t variable
            let is_time_t = var_types.get(left_text).is_some_and(|t| t == "time_t");

            if is_time_t {
                if let Some(right) = node.child_by_field_name("right") {
                    let right_text = get_node_text(&right, source);

                    // Check if right is -1 without cast
                    if right_text == "-1"
                        || (right_text.starts_with("-") && !right_text.contains("(time_t)"))
                    {
                        // Check if the -1 is properly cast
                        if !node_text.contains("(time_t)") {
                            let pos = node.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::Medium,
                                message: "Comparing time_t with -1 without proper cast".to_string(),
                                file_path: String::new(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                                suggestion: Some("Cast -1 to time_t: (time_t)-1".to_string()),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    /// A cast of a constant to an integer type, reported when the cast
    /// changes its value. True when the operand is a constant, which this
    /// settles.
    fn check_constant_cast(
        &self,
        node: &Node,
        source: &str,
        target_type: &str,
        violations: &mut Vec<RuleViolation>,
    ) -> bool {
        if target_type.contains('*') {
            return false;
        }
        let Some(value) = self
            .get_cast_operand_node(node)
            .and_then(|operand| self.constant_value(&operand, source))
        else {
            return false;
        };
        let target = target_type.replace(['(', ')'], "").trim().to_string();
        if self.constant_changes_value(value, &target) {
            let pos = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Cast of the constant {} to {} changes its value",
                    value, target
                ),
                file_path: String::new(),
                line: pos.row + 1,
                column: pos.column + 1,
                suggestion: Some("Use a value the type can represent, or a wider type".to_string()),
                ..Default::default()
            });
        }
        true
    }

    /// Whether the cast `node` of `operand` from `source_type` to `target`
    /// provably keeps the value: by its range checked as `signed` at
    /// `target_width`, or by the guards on the path to it.
    #[allow(clippy::too_many_arguments)]
    fn cast_proved_safe(
        &self,
        node: &Node,
        operand: Option<&Node>,
        source: &str,
        source_type: &str,
        target: &str,
        target_width: Option<u32>,
        signed: bool,
    ) -> bool {
        let Some(operand) = operand else {
            return false;
        };
        target_width.is_some_and(|tw| {
            self.vra_proves_conversion_safe(node, operand, source, target, tw, signed)
        }) || self.guards_prove_fit(node, operand, source, source_type, target)
    }

    fn check_cast_conversion(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, String>,
    ) {
        // Get the target type of the cast
        let mut target_type = String::new();
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "type_descriptor" {
                    target_type = get_node_text(&child, source).to_string();
                    break;
                }
            }
        }

        if self.check_constant_cast(node, source, &target_type, violations) {
            return;
        }

        // Get the source expression being cast
        let source_expr = self.get_cast_operand(node, source);

        if target_type.is_empty() || source_expr.is_empty() {
            return;
        }

        // Get source type if known
        let mut source_expr = source_expr;
        let mut source_type = var_types.get(&source_expr).cloned().unwrap_or_default();
        if source_type.is_empty() {
            // The cast operand may be a compound expression rather than a bare
            // variable, e.g. `(char)(nWord + 100)` -- the raw operand text
            // ("nWord + 100") never matches a var_types key. Resolve the
            // dominant identifier inside the operand (same helper used for
            // call-argument narrowing below) so a wide value narrowed via an
            // arithmetic expression is still caught (real example:
            // sqlite ext/misc/amatch.c `nBuf = (char)(nWord + 100);` where
            // nBuf/nWord are sqlite3_int64 and the result feeds a realloc).
            if let Some(op) = self.get_cast_operand_node(node) {
                let dominant = Self::extract_dominant_identifier(&op, source);
                if let Some(t) = var_types.get(&dominant) {
                    source_expr = dominant;
                    source_type = t.clone();
                }
            }
        }
        if source_type.is_empty() {
            // Even without a resolved source type, detect narrowing when the cast
            // operand is a shift expression (e.g., `(uint8_t)(val >> 8)`). A right-shift
            // by >= 8 bits implies the source is at least 16-bit, so casting to uint8_t
            // is a narrowing conversion that may lose data.
            self.check_shift_narrowing(node, source, &source_expr, &target_type, violations);
            return;
        }

        // Check for dangerous conversions
        let target_clean = target_type
            .replace("(", "")
            .replace(")", "")
            .trim()
            .to_string();

        // Skip pointer-type casts — not integer value conversions
        // e.g., (uint8_t *)buf is pointer reinterpretation, not a narrowing conversion
        if target_clean.contains('*') || source_type.contains('*') {
            return;
        }

        // The width the target is guaranteed: a value inside it fits wherever
        // the code is built.
        let target_width = self.get_type_width_resolved(&target_clean).map(|w| w.min);
        let target_signed = self.is_signed_type(&target_clean);
        let operand_node = self.get_cast_operand_node(node);

        // Opt-in provenance gate (mirrors INT30-C/INT32-C): a cast only loses
        // or misinterprets data dangerously when the converted value is
        // untrusted/unbounded; a bounded-local value is safe. Applies to all
        // three conversion paths below.
        if let Some(ref op_node) = operand_node {
            let definite = target_width.is_some_and(|tw| {
                self.conversion_definitely_truncates(node, op_node, source, tw, target_signed)
            });
            if !definite && !self.converted_value_is_risky(op_node, source) {
                return;
            }
        }

        // Signed to unsigned without validation
        if self.is_signed_type(&source_type) && self.is_unsigned_type(&target_clean) {
            // Suppress where the value is provably non-negative and fits.
            if self.cast_proved_safe(
                node,
                operand_node.as_ref(),
                source,
                &source_type,
                &target_clean,
                target_width,
                false,
            ) {
                return;
            }
            let pos = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Signed to unsigned conversion of '{}' without bounds check",
                    source_expr
                ),
                file_path: String::new(),
                line: pos.row + 1,
                column: pos.column + 1,
                suggestion: Some(
                    "Check that the value is non-negative before conversion".to_string(),
                ),
                ..Default::default()
            });
        }

        // Unsigned to signed without validation
        if self.is_unsigned_type(&source_type) && self.is_signed_type(&target_clean) {
            // Suppress where the value is provably inside the signed target.
            if self.cast_proved_safe(
                node,
                operand_node.as_ref(),
                source,
                &source_type,
                &target_clean,
                target_width,
                true,
            ) {
                return;
            }
            let pos = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Unsigned to signed conversion of '{}' without bounds check",
                    source_expr
                ),
                file_path: String::new(),
                line: pos.row + 1,
                column: pos.column + 1,
                suggestion: Some(
                    "Check that the value is within signed range before conversion".to_string(),
                ),
                ..Default::default()
            });
        }

        // Narrowing conversion (wide to narrow): into a character type, or
        // between two types of one signedness where the target may be the
        // narrower (`(int)` of an `ssize_t`). A change of signedness is
        // reported above.
        let same_sign_narrowing = self
            .integer_signedness(&source_type)
            .is_some_and(|s| self.integer_signedness(&target_clean) == Some(s))
            && matches!(
                (
                    self.get_type_width_resolved(&source_type),
                    self.get_type_width_resolved(&target_clean),
                ),
                (Some(from), Some(to)) if may_be_narrower(to, from)
            );
        if (self.is_wide_type(&source_type) && self.is_narrow_type(&target_clean))
            || same_sign_narrowing
        {
            // Suppress where the value provably fits the target.
            if self.cast_proved_safe(
                node,
                operand_node.as_ref(),
                source,
                &source_type,
                &target_clean,
                target_width,
                target_signed,
            ) {
                return;
            }
            let pos = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Narrowing conversion of '{}' from {} to {} without bounds check",
                    source_expr, source_type, target_clean
                ),
                file_path: String::new(),
                line: pos.row + 1,
                column: pos.column + 1,
                suggestion: Some(
                    "Check that the value is within target type range before conversion"
                        .to_string(),
                ),
                ..Default::default()
            });
        }
    }

    /// Detect narrowing when a left-shift expression is cast to a narrow type.
    /// Left-shift moves bits up, then narrow cast discards high bits = data loss.
    /// Right-shift before narrow cast is intentional byte extraction and is SAFE:
    ///   `(uint8_t)(val >> 8)` extracts the high byte — no data loss.
    fn check_shift_narrowing(
        &self,
        node: &Node,
        _source: &str,
        source_expr: &str,
        target_type: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let target_clean = target_type
            .replace("(", "")
            .replace(")", "")
            .trim()
            .to_string();
        if !self.is_narrow_type(&target_clean) {
            return;
        }

        // Right-shift before narrow cast = byte extraction = safe (FP-010).
        // Only flag left-shift before narrow cast, which loses high bits.
        if source_expr.contains("<<") && !source_expr.contains(">>") {
            let pos = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Narrowing conversion: '{}' shifted left and cast to {} may lose upper bits",
                    source_expr, target_clean
                ),
                file_path: String::new(),
                line: pos.row + 1,
                column: pos.column + 1,
                suggestion: Some(
                    "Ensure the shifted value fits in the target type or use a wider type"
                        .to_string(),
                ),
                ..Default::default()
            });
        }
    }

    fn get_cast_operand(&self, node: &Node, source: &str) -> String {
        // Find the operand of the cast (skip type_descriptor and parens)
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let kind = child.kind();
                if kind != "type_descriptor" && kind != "(" && kind != ")" {
                    return get_node_text(&child, source).to_string();
                }
            }
        }
        String::new()
    }

    fn get_cast_operand_node<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let kind = child.kind();
                if kind != "type_descriptor" && kind != "(" && kind != ")" {
                    return Some(child);
                }
            }
        }
        None
    }

    fn check_assignment_conversion(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, String>,
    ) {
        // Extract LHS name and RHS node depending on node kind
        let (lhs_name, rhs_node) = if node.kind() == "assignment_expression" {
            let left = match node.child_by_field_name("left") {
                Some(l) => l,
                None => return,
            };
            let right = match node.child_by_field_name("right") {
                Some(r) => r,
                None => return,
            };
            (get_node_text(&left, source).trim().to_string(), right)
        } else if node.kind() == "init_declarator" {
            let declarator = match node.child_by_field_name("declarator") {
                Some(d) => d,
                None => return,
            };
            let value = match node.child_by_field_name("value") {
                Some(v) => v,
                None => return,
            };
            (Self::extract_var_name(&declarator, source), value)
        } else {
            return;
        };

        if lhs_name.is_empty() {
            return;
        }

        // Get LHS type from var_types
        let lhs_type = match var_types.get(&lhs_name) {
            Some(t) => t.clone(),
            None => return,
        };

        let lhs_width = match self.get_type_width_resolved(&lhs_type) {
            Some(w) => w,
            None => return,
        };

        // A constant stored by a plain `=` or an initializer: its value, not
        // a width, says whether it survives the conversion. A cast of one is
        // the cast's conversion, which the cast check reports.
        let plain_store = node.kind() == "init_declarator"
            || node
                .child_by_field_name("operator")
                .is_some_and(|op| op.kind() == "=");
        if plain_store && unwrap_parenthesized(rhs_node).kind() != "cast_expression" {
            if let Some(value) = self.constant_value(&rhs_node, source) {
                if self.constant_changes_value(value, &lhs_type) {
                    let pos = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Conversion of the constant {} to '{}' ({}) changes its value",
                            value, lhs_name, lhs_type
                        ),
                        file_path: String::new(),
                        line: pos.row + 1,
                        column: pos.column + 1,
                        suggestion: Some(
                            "Store a value the type can represent, or use a wider type".to_string(),
                        ),
                        ..Default::default()
                    });
                }
                return;
            }
        }

        let rhs_width = match self.infer_rhs_width(&rhs_node, source, var_types) {
            Some(w) => w,
            None => return,
        };

        // No narrowing: the target cannot be narrower than the value on any
        // target the data model allows (a `long long` into a `long` may lose
        // bits on LLP64, so under ISO C's widths it is narrowing).
        if !may_be_narrower(lhs_width, rhs_width) {
            return;
        }
        let lhs_width_type = lhs_width;
        let lhs_width = lhs_width.min;

        // Suppression: RHS has a narrowing cast whose target width <= LHS width
        // (check_cast_conversion already flags this)
        if self.rhs_has_narrowing_cast_to(&rhs_node, source, lhs_width_type) {
            return;
        }
        if self.bitwise_store_fits(node, &rhs_node, source, &lhs_type) {
            return;
        }

        // VRA suppression: if RHS value provably fits in LHS type, suppress
        let lhs_signed = self.is_signed_type(&lhs_type);
        if self
            .vra_proves_conversion_safe(node, &rhs_node, source, &lhs_type, lhs_width, lhs_signed)
        {
            return;
        }
        if let Some(rhs_type) = Self::rhs_variable_type(&rhs_node, source, var_types) {
            if self.guards_prove_fit(node, &rhs_node, source, &rhs_type, &lhs_type) {
                return;
            }
        }

        // Opt-in provenance gate (mirrors INT30-C/INT32-C): only flag a
        // narrowing assignment when the RHS derives from untrusted/unbounded
        // input. A bounded-local wider value rarely actually loses data.
        if !self.conversion_definitely_truncates(node, &rhs_node, source, lhs_width, lhs_signed)
            && !self.converted_value_is_risky(&rhs_node, source)
        {
            return;
        }

        let pos = node.start_position();
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "Implicit narrowing conversion: assigning wider type to '{}' ({})",
                lhs_name, lhs_type
            ),
            file_path: String::new(),
            line: pos.row + 1,
            column: pos.column + 1,
            suggestion: Some(
                "Add an explicit bounds check or use an explicit narrowing cast".to_string(),
            ),
            ..Default::default()
        });
    }

    /// The declared type of `rhs` when it is a variable, through any
    /// parentheses.
    fn rhs_variable_type(
        rhs: &Node,
        source: &str,
        var_types: &HashMap<String, String>,
    ) -> Option<String> {
        let rhs = unwrap_parenthesized(*rhs);
        (rhs.kind() == "identifier")
            .then(|| var_types.get(get_node_text(&rhs, source).trim()).cloned())
            .flatten()
    }

    /// Whether the value a bitwise store leaves in `target_type` fits it by
    /// its operands. `a & b` lies between 0 and any operand that is not
    /// negative, so one operand the target holds bounds it; `a | b` and
    /// `a ^ b` need both. A compound `x &= m` has `x` as its left operand,
    /// so an unsigned `x` bounds what is stored back into it.
    fn bitwise_store_fits(&self, store: &Node, rhs: &Node, source: &str, target: &str) -> bool {
        let compound = store
            .child_by_field_name("operator")
            .map(|op| op.kind())
            .and_then(|op| op.strip_suffix('='))
            .filter(|op| !op.is_empty());
        match (compound, store.child_by_field_name("left")) {
            (Some(op), Some(left)) => self.bitwise_fits(op, &[left, *rhs], source, target),
            _ => self.operand_fits(rhs, source, target),
        }
    }

    /// [`Self::bitwise_store_fits`] for the operator `op` on `operands`.
    fn bitwise_fits(&self, op: &str, operands: &[Node], source: &str, target: &str) -> bool {
        match op {
            "&" => operands
                .iter()
                .any(|o| self.operand_fits(o, source, target)),
            "|" | "^" => operands
                .iter()
                .all(|o| self.operand_fits(o, source, target)),
            _ => false,
        }
    }

    /// Whether `operand` is a value that is never negative and that
    /// `target` holds: a non-negative constant inside it, a value of an
    /// unsigned type no wider than it (and narrower on every implementation,
    /// for a target that may be signed), or a bitwise result of such.
    fn operand_fits(&self, operand: &Node, source: &str, target: &str) -> bool {
        let operand = unwrap_parenthesized(*operand);
        if operand.kind() == "binary_expression" {
            return match (
                operand.child_by_field_name("operator"),
                operand.child_by_field_name("left"),
                operand.child_by_field_name("right"),
            ) {
                (Some(op), Some(left), Some(right)) => {
                    self.bitwise_fits(op.kind(), &[left, right], source, target)
                }
                _ => false,
            };
        }
        if let Some(value) = self.constant_value(&operand, source) {
            return value >= 0 && !self.constant_changes_value(value, target);
        }
        let Some(spelling) = operand_type_spelling(&operand, source) else {
            return false;
        };
        if !self.is_unsigned_type(&spelling) {
            return false;
        }
        let (Some(from), Some(to)) = (
            self.get_type_width_resolved(&spelling),
            self.get_type_width_resolved(target),
        ) else {
            return false;
        };
        if may_be_narrower(to, from) {
            return false;
        }
        let target_unsigned = match self.plain_char_signedness(target) {
            Some(declared) => declared == Some(false),
            None => self.is_unsigned_type(target),
        };
        target_unsigned || from.max.is_some_and(|bits| bits < to.min)
    }

    /// Infer the bit-width of the RHS expression.
    fn infer_rhs_width(
        &self,
        node: &Node,
        source: &str,
        var_types: &HashMap<String, String>,
    ) -> Option<IntWidth> {
        match node.kind() {
            "cast_expression" => {
                // Extract the cast target type
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "type_descriptor" {
                            let type_text = get_node_text(&child, source)
                                .replace("(", "")
                                .replace(")", "")
                                .trim()
                                .to_string();
                            return self.get_type_width_resolved(&type_text);
                        }
                    }
                }
                None
            }
            "identifier" => {
                let name = get_node_text(node, source).to_string();
                var_types
                    .get(&name)
                    .and_then(|t| self.get_type_width_resolved(t))
            }
            "parenthesized_expression" => {
                // Unwrap parens and recurse
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() != "(" && child.kind() != ")" {
                            return self.infer_rhs_width(&child, source, var_types);
                        }
                    }
                }
                None
            }
            "binary_expression" => {
                let op = node.child_by_field_name("operator")?;
                let left = node.child_by_field_name("left")?;
                let right = node.child_by_field_name("right")?;
                match op.kind() {
                    "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" => {
                        self.promoted_width(&[left, right], source, var_types)
                    }
                    // A shift has its left operand's promoted type.
                    "<<" | ">>" => self.promoted_width(&[left], source, var_types),
                    // A comparison or logical operator yields 0 or 1.
                    _ => None,
                }
            }
            "unary_expression" => {
                let op = node.child_by_field_name("operator")?;
                let argument = node.child_by_field_name("argument")?;
                match op.kind() {
                    "-" | "+" | "~" => self.promoted_width(&[argument], source, var_types),
                    _ => None,
                }
            }
            "number_literal" => None,
            _ => None,
        }
    }

    /// The width of arithmetic on `operands` after the integer promotions
    /// and the usual arithmetic conversions: at least `int`'s, and the
    /// widest operand's where that is wider. An operand of unknown type
    /// counts as `int`, which can only understate the width.
    fn promoted_width(
        &self,
        operands: &[Node],
        source: &str,
        var_types: &HashMap<String, String>,
    ) -> Option<IntWidth> {
        let mut width = self.get_type_width_resolved("int")?;
        for operand in operands {
            if let Some(w) = self.infer_rhs_width(operand, source, var_types) {
                if may_be_narrower(width, w) {
                    width = w;
                }
            }
        }
        Some(width)
    }

    /// The value of `node` when it is an integer constant: a literal, a
    /// macro, or arithmetic on them. None for a character literal, whose
    /// store into a character type is CERT's EX2.
    fn constant_value(&self, node: &Node, source: &str) -> Option<i64> {
        let node = unwrap_parenthesized(*node);
        if node.kind() == "char_literal" {
            return None;
        }
        let macros = self.current_macros.borrow();
        let value = const_eval::try_evaluate_range(&node, source, &macros, &Default::default())
            .filter(|r| r.min == r.max)
            .map(|r| r.min)?;
        if value >= 0 {
            return Some(value);
        }
        // An unsigned constant (`~0U`, `0U - 1`) is its value modulo the
        // type's width, unknown where the data model leaves that open.
        let model = self.data_model.get();
        let typedefs = self.typedef_types.borrow();
        let (fields, aliases) = (HashMap::new(), HashMap::new());
        let env = expr_type::TypeEnv::new(&typedefs, &fields, &fields, &aliases, model);
        let bits = match expr_type::expr_type(&node, source, &env) {
            Some(CType::Int {
                sign: Sign::Unsigned,
                rank,
            }) => model.exact_width(rank),
            Some(CType::IntOfWidth {
                sign: Sign::Unsigned,
                max_bits,
                ..
            }) => max_bits,
            _ => return Some(value),
        };
        bits.filter(|&b| b < 63)
            .map(|b| value.rem_euclid(1i64 << b))
    }

    /// Whether converting the constant `value` to `target_type` changes it.
    /// A negative constant into an unsigned type at least as wide as `int`
    /// is CERT's EX3, and a `_Bool` target is a truth-value conversion.
    fn constant_changes_value(&self, value: i64, target_type: &str) -> bool {
        let target = target_type.trim();
        if matches!(target, "_Bool" | "bool") {
            return false;
        }
        let Some(width) = self.get_type_width_resolved(target) else {
            return false;
        };
        if width.min == FLOAT_AS_INTEGER_WIDTH {
            return false;
        }
        let bits = width.min;
        if bits == 0 || bits >= 64 {
            return false;
        }
        let signed_range = -(1i64 << (bits - 1))..=(1i64 << (bits - 1)) - 1;
        let unsigned_range = 0..=(1i64 << bits) - 1;
        if let Some(char_signed) = self.plain_char_signedness(target) {
            return match char_signed {
                Some(true) => !signed_range.contains(&value),
                Some(false) => !unsigned_range.contains(&value),
                None => !(signed_range.contains(&value) && unsigned_range.contains(&value)),
            };
        }
        if self.is_signed_type(target) {
            !signed_range.contains(&value)
        } else if self.is_unsigned_type(target) {
            if value < 0 {
                // EX3 needs the target at least as wide as `int`. A type the
                // model gives neither a rank nor an exact width (`size_t`
                // under ISO C's widths) is read by the widths guaranteed.
                let Some(int) = self.get_type_width_resolved("int") else {
                    return true;
                };
                let open = width.rank.is_none() && width.max.is_none();
                may_be_narrower(width, int) && !(open && width.min >= int.min)
            } else {
                value > (1i64 << bits) - 1
            }
        } else {
            false
        }
    }

    /// Check if RHS is a cast_expression whose target width <= LHS width.
    /// If so, check_cast_conversion() already handles it — don't double-flag.
    fn rhs_has_narrowing_cast_to(&self, node: &Node, source: &str, lhs_width: IntWidth) -> bool {
        let check = node;
        if check.kind() == "cast_expression" {
            for i in 0..check.child_count() {
                if let Some(child) = check.child(i) {
                    if child.kind() == "type_descriptor" {
                        let type_text = get_node_text(&child, source)
                            .replace("(", "")
                            .replace(")", "")
                            .trim()
                            .to_string();
                        if let Some(cast_width) = self.get_type_width_resolved(&type_text) {
                            return !may_be_narrower(lhs_width, cast_width);
                        }
                    }
                }
            }
        }
        // Also check through parenthesized expressions
        if check.kind() == "parenthesized_expression" {
            for i in 0..check.child_count() {
                if let Some(child) = check.child(i) {
                    if child.kind() != "(" && child.kind() != ")" {
                        return self.rhs_has_narrowing_cast_to(&child, source, lhs_width);
                    }
                }
            }
        }
        false
    }

    /// Extract the dominant identifier from an expression for bounds-check lookup.
    /// For `(uint16_t)(buffer[i])`, this extracts "buffer".
    /// For `some_var`, this extracts "some_var".
    fn extract_dominant_identifier(node: &Node, source: &str) -> String {
        match node.kind() {
            "identifier" => get_node_text(node, source).to_string(),
            "cast_expression" => {
                // Get the operand (skip type_descriptor and parens)
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        let kind = child.kind();
                        if kind != "type_descriptor" && kind != "(" && kind != ")" {
                            return Self::extract_dominant_identifier(&child, source);
                        }
                    }
                }
                String::new()
            }
            "parenthesized_expression" => {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() != "(" && child.kind() != ")" {
                            return Self::extract_dominant_identifier(&child, source);
                        }
                    }
                }
                String::new()
            }
            _ => {
                // For complex expressions, try to find the first identifier child
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "identifier" {
                            return get_node_text(&child, source).to_string();
                        }
                    }
                }
                String::new()
            }
        }
    }

    /// Whether `type_str` names a signed integer type: its specifier words,
    /// a signed alias by its whole name (`ssize_t`, `int32_t`), or a typedef
    /// whose chain ends at one. A name is never matched as a substring of
    /// another, so `uint32_t` is not `int` and `ssize_t` is not `size_t`.
    fn is_signed_type(&self, type_str: &str) -> bool {
        self.integer_signedness(type_str) == Some(true)
    }

    /// Whether `type_str` names an unsigned integer type, as
    /// [`Self::is_signed_type`] reads it.
    fn is_unsigned_type(&self, type_str: &str) -> bool {
        self.integer_signedness(type_str) == Some(false)
    }

    /// `Some(true)` for a signed integer type, `Some(false)` for an unsigned
    /// one, `None` for plain `char`, a pointer, or a name it does not know.
    fn integer_signedness(&self, type_str: &str) -> Option<bool> {
        if let Some(signed) = spelled_signedness(type_str) {
            return Some(signed);
        }
        let core = type_core(type_str);
        let typedefs = self.typedef_types.borrow();
        let resolved =
            crate::utility::cert_c::overflow_helpers::resolve_typedef_chain(&core, &typedefs);
        if resolved == core {
            return None;
        }
        spelled_signedness(&resolved)
    }

    fn is_narrow_type(&self, type_str: &str) -> bool {
        let normalized = type_str.to_lowercase();
        for t in NARROW_TYPES {
            if normalized.contains(&t.to_lowercase()) {
                return true;
            }
        }
        false
    }

    fn is_wide_type(&self, type_str: &str) -> bool {
        let normalized = type_str.to_lowercase();
        for t in WIDE_TYPES {
            if normalized.contains(&t.to_lowercase()) {
                return true;
            }
        }
        false
    }
}

/// The `<limits.h>` and `<stdint.h>` limit macros, each with the type whose
/// limit it is and whether it is that type's largest value (else its
/// smallest).
const LIMIT_MACROS: &[(&str, &str, bool)] = &[
    ("SCHAR_MAX", "signed char", true),
    ("SCHAR_MIN", "signed char", false),
    ("UCHAR_MAX", "unsigned char", true),
    ("SHRT_MAX", "short", true),
    ("SHRT_MIN", "short", false),
    ("USHRT_MAX", "unsigned short", true),
    ("INT_MAX", "int", true),
    ("INT_MIN", "int", false),
    ("UINT_MAX", "unsigned int", true),
    ("LONG_MAX", "long", true),
    ("LONG_MIN", "long", false),
    ("ULONG_MAX", "unsigned long", true),
    ("LLONG_MAX", "long long", true),
    ("LLONG_MIN", "long long", false),
    ("ULLONG_MAX", "unsigned long long", true),
    ("INT8_MAX", "int8_t", true),
    ("INT8_MIN", "int8_t", false),
    ("UINT8_MAX", "uint8_t", true),
    ("INT16_MAX", "int16_t", true),
    ("INT16_MIN", "int16_t", false),
    ("UINT16_MAX", "uint16_t", true),
    ("INT32_MAX", "int32_t", true),
    ("INT32_MIN", "int32_t", false),
    ("UINT32_MAX", "uint32_t", true),
    ("INT64_MAX", "int64_t", true),
    ("INT64_MIN", "int64_t", false),
    ("UINT64_MAX", "uint64_t", true),
    ("SIZE_MAX", "size_t", true),
];

/// A conversion's target, as the guards before it are read against.
struct Target {
    width: IntWidth,
    signed: bool,
    /// The largest value every implementation gives the target.
    max: i64,
    /// The smallest value every implementation gives the target.
    min: i64,
}

/// What a governing condition establishes about a variable against a
/// target: that it is at least the target's smallest value, and that it is
/// at most its largest.
#[derive(Default, Clone, Copy)]
struct Bounds {
    lower: bool,
    upper: bool,
}

impl Bounds {
    fn or(self, other: Bounds) -> Bounds {
        Bounds {
            lower: self.lower || other.lower,
            upper: self.upper || other.upper,
        }
    }
}

impl Int31C {
    /// Whether the conditions governing `site` keep the variable `operand`
    /// inside `target_type`, from a `source_type` value: each side the
    /// conversion can lose on is bounded by a condition, read with the
    /// polarity the path to `site` gives it, against a number inside the
    /// target or a limit macro that is inside it on every implementation
    /// (`SCHAR_MAX` for a `short`, `UCHAR_MAX` for a `uint8_t`). This is
    /// what credits CERT's own guards under ISO C's widths, where
    /// `UCHAR_MAX` is no number for value-range analysis to compare with.
    /// A condition counts only when nothing writes the variable between it
    /// and `site`.
    fn guards_prove_fit(
        &self,
        site: &Node,
        operand: &Node,
        source: &str,
        source_type: &str,
        target_type: &str,
    ) -> bool {
        let operand = unwrap_parenthesized(*operand);
        if operand.kind() != "identifier" {
            return false;
        }
        let var = Object::of(&operand, source);
        let (Some(source_width), Some(target_width)) = (
            self.get_type_width_resolved(source_type),
            self.get_type_width_resolved(target_type),
        ) else {
            return false;
        };
        let source_signed = self.is_signed_type(source_type);
        // A plain `char` the project has not declared either way keeps only
        // a value that fits it whichever way the build has it.
        let readings: &[bool] = match self.plain_char_signedness(target_type) {
            Some(Some(true)) => &[true],
            Some(Some(false)) => &[false],
            Some(None) => &[true, false],
            None if self.is_signed_type(target_type) => &[true],
            None => &[false],
        };
        readings.iter().all(|&target_signed| {
            self.guards_prove_fit_as(
                site,
                &var,
                source,
                source_width,
                target_width,
                source_signed,
                target_signed,
            )
        })
    }

    /// [`Self::guards_prove_fit`] for a target of the given signedness.
    #[allow(clippy::too_many_arguments)]
    fn guards_prove_fit_as(
        &self,
        site: &Node,
        var: &Object,
        source: &str,
        source_width: IntWidth,
        target_width: IntWidth,
        source_signed: bool,
        target_signed: bool,
    ) -> bool {
        let narrower = may_be_narrower(target_width, source_width);
        let need_lower = source_signed && (!target_signed || narrower);
        let need_upper = narrower || (!source_signed && target_signed);
        if !need_lower && !need_upper {
            return true;
        }
        let bits = target_width.min;
        if bits == 0 || bits > 63 {
            return false;
        }
        let target = Target {
            width: target_width,
            signed: target_signed,
            max: if target_signed {
                (1i64 << (bits - 1)) - 1
            } else {
                (1i64 << bits) - 1
            },
            min: if target_signed {
                -((1i64 << (bits - 1)) - 1)
            } else {
                0
            },
        };
        let Some(function) = ast_utils::find_containing_function(site) else {
            return false;
        };
        let mut bounds = Bounds::default();
        for (condition, branch) in guard_dominance::dominating_conditions_with_branches(site) {
            let Some(truth) = branch else {
                continue;
            };
            if written_between(&function, var, condition.end_byte(), site, source) {
                continue;
            }
            bounds = bounds.or(self.condition_bounds(&condition, var, truth, &target, source));
        }
        (bounds.lower || !need_lower) && (bounds.upper || !need_upper)
    }

    /// What `condition`, evaluated `truth`, says about `var` against
    /// `target`. A true `&&` and a false `||` make each side a fact, `!`
    /// flips the truth, and a comparison of `var` with a bound in either
    /// order is a fact on one side.
    fn condition_bounds(
        &self,
        condition: &Node,
        var: &Object,
        truth: bool,
        target: &Target,
        source: &str,
    ) -> Bounds {
        let condition = unwrap_parenthesized(*condition);
        match condition.kind() {
            "unary_expression" => {
                let negates = condition
                    .child_by_field_name("operator")
                    .is_some_and(|op| op.kind() == "!");
                match condition.child_by_field_name("argument") {
                    Some(argument) if negates => {
                        self.condition_bounds(&argument, var, !truth, target, source)
                    }
                    _ => Bounds::default(),
                }
            }
            "binary_expression" => {
                let (Some(op), Some(left), Some(right)) = (
                    condition.child_by_field_name("operator"),
                    condition.child_by_field_name("left"),
                    condition.child_by_field_name("right"),
                ) else {
                    return Bounds::default();
                };
                match op.kind() {
                    "&&" if truth => self
                        .condition_bounds(&left, var, true, target, source)
                        .or(self.condition_bounds(&right, var, true, target, source)),
                    "||" if !truth => self
                        .condition_bounds(&left, var, false, target, source)
                        .or(self.condition_bounds(&right, var, false, target, source)),
                    "<" | "<=" | ">" | ">=" | "==" | "!=" => {
                        let is_var = |n: &Node| var.is(n, source);
                        let (op, occurrence, bound) = if is_var(&left) {
                            (op.kind(), left, right)
                        } else if is_var(&right) {
                            (flip_comparison(op.kind()), right, left)
                        } else {
                            return Bounds::default();
                        };
                        let op = if truth { op } else { negate_comparison(op) };
                        let bounds = self.comparison_bounds(op, &bound, target, source);
                        let below = matches!(op, "<" | "<=");
                        // Compared as unsigned, a negative value reads as a
                        // large one: `x < B` then also says `x` is not
                        // negative, and `x >= B` or `x == B` says nothing.
                        match self.compared_as_unsigned(&occurrence, &bound, source) {
                            Some(false) => bounds,
                            Some(true) => Bounds {
                                lower: below,
                                upper: below && bounds.upper,
                            },
                            None => Bounds {
                                lower: false,
                                upper: below && bounds.upper,
                            },
                        }
                    }
                    _ => Bounds::default(),
                }
            }
            _ => Bounds::default(),
        }
    }

    /// Whether comparing `occurrence`, a signed variable, with `bound`
    /// converts it to unsigned (C11 6.3.1.8): `Some(true)` when the bound is
    /// an unsigned type at least as wide as both `int` and the variable on
    /// every implementation, `Some(false)` when the comparison is signed
    /// (an unsigned variable, a bound not known to be unsigned, or one that
    /// promotes to `int`), and `None` when the data model leaves it open.
    fn compared_as_unsigned(&self, occurrence: &Node, bound: &Node, source: &str) -> Option<bool> {
        let Some(var_type) = operand_type_spelling(occurrence, source) else {
            return Some(false);
        };
        if !self.is_signed_type(&var_type) {
            return Some(false);
        }
        let Some(bound_type) = self.bound_type_spelling(bound, source) else {
            return Some(false);
        };
        if !self.is_unsigned_type(&bound_type) {
            return Some(false);
        }
        let (Some(bound_width), Some(var_width), Some(int_width)) = (
            self.get_type_width_resolved(&bound_type),
            self.get_type_width_resolved(&var_type),
            self.get_type_width_resolved("int"),
        ) else {
            return None;
        };
        if bound_width.max.is_some_and(|bits| bits < int_width.min) {
            return Some(false);
        }
        if !may_be_narrower(bound_width, var_width) && !may_be_narrower(bound_width, int_width) {
            return Some(true);
        }
        None
    }

    /// The type of a comparison's bound, as spelled: a limit macro's type,
    /// an integer constant's type (an unsigned suffix, or a hexadecimal
    /// value past `int`), or what [`operand_type_spelling`] reads.
    fn bound_type_spelling(&self, bound: &Node, source: &str) -> Option<String> {
        let bound = unwrap_parenthesized(*bound);
        let text = get_node_text(&bound, source).trim();
        if let Some((_, ty, _)) = LIMIT_MACROS.iter().find(|(name, _, _)| *name == text) {
            return Some(ty.to_string());
        }
        if bound.kind() == "number_literal" {
            let (sign, rank) = match expr_type::number_literal_type(text, self.data_model.get())? {
                CType::Int { sign, rank } => (sign, rank),
                _ => return None,
            };
            let rank = match rank {
                Rank::Int => "int",
                Rank::Long => "long",
                Rank::LongLong => "long long",
                _ => return None,
            };
            return Some(match sign {
                Sign::Unsigned => format!("unsigned {rank}"),
                _ => rank.to_string(),
            });
        }
        operand_type_spelling(&bound, source)
    }

    /// What `var OP bound`, known true, says about `var` against `target`.
    fn comparison_bounds(&self, op: &str, bound: &Node, target: &Target, source: &str) -> Bounds {
        let bound = unwrap_parenthesized(*bound);
        let text = get_node_text(&bound, source).trim().to_string();
        let limit = LIMIT_MACROS.iter().find(|(name, _, _)| *name == text);
        let value = || {
            let macros = self.current_macros.borrow();
            const_eval::try_evaluate_range(&bound, source, &macros, &Default::default())
                .filter(|r| r.min == r.max)
                .map(|r| r.min)
        };
        let upper = matches!(op, "<" | "<=" | "==")
            && match limit {
                Some((_, ty, true)) => self.limit_max_within(ty, target),
                Some(_) => false,
                None => value().is_some_and(|v| {
                    let largest = if op == "<" { v.saturating_sub(1) } else { v };
                    largest <= target.max
                }),
            };
        let lower = matches!(op, ">" | ">=" | "==")
            && match limit {
                Some((_, ty, false)) => self.limit_min_within(ty, target),
                Some(_) => false,
                None => value().is_some_and(|v| {
                    let smallest = if op == ">" { v.saturating_add(1) } else { v };
                    smallest >= target.min
                }),
            };
        Bounds { lower, upper }
    }

    /// The width of the type a limit macro belongs to, as compared with a
    /// target of exactly 8 bits: a `(u)int8_t` exists only where a byte is
    /// 8 bits, so the character types are 8 bits wherever it does.
    fn limit_width(&self, limit_type: &str, target: &Target) -> Option<IntWidth> {
        let width = self.get_type_width_resolved(limit_type)?;
        let byte = matches!(limit_type, "signed char" | "unsigned char");
        if byte && target.width.max == Some(8) && target.width.min == 8 {
            return Some(IntWidth {
                rank: width.rank,
                min: 8,
                max: Some(8),
            });
        }
        Some(width)
    }

    /// Whether the largest value of `limit_type` is at most the target's on
    /// every implementation.
    fn limit_max_within(&self, limit_type: &str, target: &Target) -> bool {
        let Some(width) = self.limit_width(limit_type, target) else {
            return false;
        };
        let limit_signed = self.is_signed_type(limit_type);
        if may_be_narrower(target.width, width) {
            return false;
        }
        // An unsigned type's largest value can pass a signed type's of the
        // same width.
        limit_signed || !target.signed || width.max.is_some_and(|w| w < target.width.min)
    }

    /// Whether the smallest value of `limit_type`, a signed type, is at
    /// least the target's on every implementation.
    fn limit_min_within(&self, limit_type: &str, target: &Target) -> bool {
        let Some(width) = self.limit_width(limit_type, target) else {
            return false;
        };
        target.signed && !may_be_narrower(target.width, width)
    }
}

/// `node` with any parentheses around it removed.
fn unwrap_parenthesized(mut node: Node) -> Node {
    while node.kind() == "parenthesized_expression" {
        match node.named_child(0) {
            Some(inner) => node = inner,
            None => break,
        }
    }
    node
}

/// The type `operand` has before any promotion, as spelled: the type the
/// declaration an identifier resolves to gives it there (ADR-0006), a cast's
/// type, or the type POSIX fixes for a byte-order call's result.
fn operand_type_spelling(operand: &Node, source: &str) -> Option<String> {
    let operand = unwrap_parenthesized(*operand);
    match operand.kind() {
        "identifier" => ast_utils::resolve_identifier_declared_type(
            &operand,
            get_node_text(&operand, source).trim(),
            source,
        ),
        "cast_expression" => operand
            .child_by_field_name("type")
            .map(|t| get_node_text(&t, source).to_string()),
        "call_expression" => {
            let callee = operand.child_by_field_name("function")?;
            (callee.kind() == "identifier")
                .then(|| {
                    std_functions::byte_order_return_type(get_node_text(&callee, source).trim())
                })
                .flatten()
                .map(str::to_string)
        }
        _ => None,
    }
}

/// The comparison `b OP a` means as `a OP' b`.
fn flip_comparison(op: &str) -> &str {
    match op {
        "<" => ">",
        "<=" => ">=",
        ">" => "<",
        ">=" => "<=",
        other => other,
    }
}

/// The comparison that holds where `a OP b` is false.
fn negate_comparison(op: &str) -> &str {
    match op {
        "<" => ">=",
        "<=" => ">",
        ">" => "<=",
        ">=" => "<",
        "==" => "!=",
        _ => "==",
    }
}

/// One object a conversion reads, as the declaration its occurrence
/// resolves to: another occurrence is the same object only when it resolves
/// to the same declaration, so an inner `x` that hides the guarded one is
/// not it (ADR-0006).
struct Object<'s> {
    name: &'s str,
    declarator: Option<usize>,
}

impl<'s> Object<'s> {
    /// The object the identifier `ident` names.
    fn of(ident: &Node, source: &'s str) -> Self {
        let name = get_node_text(ident, source).trim();
        Object {
            name,
            declarator: Self::binding(ident, name, source),
        }
    }

    fn binding(ident: &Node, name: &str, source: &str) -> Option<usize> {
        ast_utils::resolve_identifier_declarator(ident, name, source).map(|(_, d)| d.id())
    }

    /// Whether `node`, through any parentheses, is an occurrence of this
    /// object.
    fn is(&self, node: &Node, source: &str) -> bool {
        let node = unwrap_parenthesized(*node);
        node.kind() == "identifier"
            && get_node_text(&node, source).trim() == self.name
            && Self::binding(&node, self.name, source) == self.declarator
    }
}

/// Whether `function` writes `var` (an assignment to it, `++`/`--`, its
/// address taken, or a declaration initializing it) where the write reaches
/// `site` from a condition ending at `from`: anywhere from `from` to `site`,
/// and, for a loop around `site` that begins after `from`, anywhere in the
/// loop, since a write after `site` reaches it on the next iteration.
fn written_between(function: &Node, var: &Object, from: usize, site: &Node, source: &str) -> bool {
    let mut to = site.start_byte();
    let mut ancestor = site.parent();
    while let Some(a) = ancestor {
        if a.start_byte() < from {
            break;
        }
        if matches!(
            a.kind(),
            "while_statement" | "for_statement" | "do_statement"
        ) {
            to = to.max(a.end_byte());
        }
        ancestor = a.parent();
    }
    if from >= to {
        return false;
    }
    let names = |n: Option<Node>| n.is_some_and(|n| var.is(&n, source));
    query::find_descendants_of_kinds(
        *function,
        &[
            "assignment_expression",
            "update_expression",
            "pointer_expression",
            "init_declarator",
        ],
    )
    .into_iter()
    .filter(|n| n.start_byte() >= from && n.start_byte() < to)
    .any(|n| match n.kind() {
        "assignment_expression" => names(n.child_by_field_name("left")),
        "update_expression" => names(n.child_by_field_name("argument")),
        "init_declarator" => names(n.child_by_field_name("declarator")),
        _ => {
            n.child_by_field_name("operator")
                .is_some_and(|op| op.kind() == "&")
                && names(n.child_by_field_name("argument"))
        }
    })
}
