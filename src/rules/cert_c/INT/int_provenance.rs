//! Shared operand-provenance analysis for the INT overflow/wrap rules
//! (INT30-C unsigned wrap, INT32-C signed overflow).
//!
//! Implements the *opt-in* taint gate: an arithmetic operation is flagged only
//! when at least one operand derives from untrusted or unbounded input — a
//! taint source, a full-range parser, an untrusted-decode accessor, a
//! tainted-summary callee return, a tainted global, or a parameter no caller
//! bounds. Bounded local state (loop counters, register/cursor indices,
//! struct-field counts) is treated as practically non-overflowing, which is
//! what eliminates the bounded-counter false positives that dominate hardened
//! codebases.
//!
//! The rule-specific pieces (which VRA width to check, how to compute a
//! definite-overflow signal, the per-function memo) stay in each rule; this
//! module holds only the provenance classification, which is identical across
//! the signed and unsigned rules.

use crate::analyze::context::SummaryLookup;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::std_functions;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// Interprocedural context for classifying a bare `identifier` operand that
/// names a parameter of the enclosing function.
///
/// A parameter holds whatever its callers pass, so its provenance is a
/// property of the call sites and cannot be read off the function body. Pass
/// `None` where no cross-file context exists (a scan without `-d`, or a
/// consumer that never built one); that keeps the older policy, under which
/// every parameter counts as bounded local state.
pub struct ParamContext<'a> {
    /// Name of the function whose body the operand sits in.
    pub func_name: &'a str,
    /// Parameter names of that function, in declaration order: a call site
    /// is matched to a parameter by position.
    pub params: &'a [String],
}

/// True when `callee` (any function-reference text) names a source of untrusted
/// or full-range values: a full-range integer parser (`atoi`/`strtol`/`rand`),
/// an untrusted-decode accessor (varint decoders — see
/// [`std_functions::is_untrusted_decode_function`]), a standard environment/IO
/// taint source (`scanf`/`recv`/`fgets`/...), or a project-local function whose
/// prescan summary carries taint (`has_env03_taint_source` directly or
/// `returns_tainted` transitively).
pub fn callee_is_risky_source(callee: &str, summaries: &(impl SummaryLookup + ?Sized)) -> bool {
    let ident = callee
        .rsplit(|c: char| !c.is_alphanumeric() && c != '_')
        .next()
        .unwrap_or(callee)
        .trim();
    if std_functions::is_full_range_return_function(ident)
        || std_functions::is_untrusted_decode_function(ident)
    {
        return true;
    }
    if crate::analyze::function_summary::ENV03_TAINT_SOURCE_FUNCTIONS.contains(&ident) {
        return true;
    }
    matches!(summaries.get(ident), Some(s) if s.has_env03_taint_source || s.returns_tainted)
}

/// True when parameter `idx` of `func_name` must be treated as carrying
/// untrusted or unbounded input: judged by what every caller passes there,
/// exactly as [`operand_is_risky`] would judge that argument in the caller's
/// own body ([`crate::analyze::arg_origin::param_is_risky`]).
///
/// Risky whenever the scan cannot say what reaches it: a caller set that is
/// open (external linkage, or an address that escapes; ADR-0011), a caller
/// the record does not describe, no caller at all, or a caller whose argument
/// derives from a risky source ([`callee_is_risky_source`], which counts the
/// full-range parsers such as `rand` and `atoi` as the caller's own body
/// would) or from a tainted global. An argument that forwards the caller's
/// own parameter is judged up the chain.
///
/// Not risky is the gate's reporting scope, not a proof that the value fits:
/// a constant every caller passes reaches the value-range check through the
/// parameter's entry range, which decides the arithmetic either way.
pub fn parameter_is_risky(
    func_name: &str,
    idx: usize,
    summaries: &(impl SummaryLookup + ?Sized),
    global_writers: &HashMap<String, HashSet<String>>,
) -> bool {
    crate::analyze::arg_origin::param_is_risky(func_name, idx, summaries, |origin| {
        origin_is_risky(origin, summaries, global_writers)
    })
}

/// Whether one caller's argument derives from a risky source: a risky callee
/// reaches it, or it reads a global a tainted function writes.
pub fn origin_is_risky(
    origin: &crate::analyze::arg_origin::ArgOrigin,
    summaries: &(impl SummaryLookup + ?Sized),
    global_writers: &HashMap<String, HashSet<String>>,
) -> bool {
    origin
        .calls
        .iter()
        .any(|callee| callee_is_risky_source(callee, summaries))
        || origin
            .names
            .iter()
            .any(|name| global_is_tainted(name, global_writers, summaries))
}

/// Walk `body` ONCE and collect every variable name fed from a risky source:
///   - `var = riskyCall(...)` or `T var = riskyCall(...)` (return-value flow), or
///   - `riskySource(..., &var, ...)` / `riskySource(..., var, ...)` (fill by
///     reference, e.g. `fscanf(stdin, "%d", &data)`, `recv(fd, buf, ...)`).
///
/// Intended to be memoized per function by the caller, so this O(body) walk runs
/// once per function rather than once per arithmetic operand.
pub fn collect_risky_vars(
    body: &Node,
    summaries: &(impl SummaryLookup + ?Sized),
    source: &str,
) -> HashSet<String> {
    crate::analyze::arg_origin::variable_feeders(body, source)
        .into_iter()
        .filter(|(_, callees)| {
            callees
                .iter()
                .any(|callee| callee_is_risky_source(callee, summaries))
        })
        .map(|(name, _)| name)
        .collect()
}

/// Classify a single operand subtree's provenance against the precomputed
/// risky-variable set. `global_writers` maps a global name to the functions that
/// write it; a global operand is risky when any writer carries taint. `params`,
/// when present, extends the judgement to parameters via the call graph — see
/// [`ParamContext`] and [`parameter_is_risky`].
pub fn operand_is_risky(
    op: &Node,
    risky_vars: &HashSet<String>,
    summaries: &(impl SummaryLookup + ?Sized),
    global_writers: &HashMap<String, HashSet<String>>,
    params: Option<&ParamContext>,
    source: &str,
) -> bool {
    match op.kind() {
        "call_expression" => match op.child_by_field_name("function") {
            Some(f) => callee_is_risky_source(&get_node_text(&f, source), summaries),
            None => false,
        },
        "identifier" => {
            let name = get_node_text(op, source);
            if risky_vars.contains(name) || global_is_tainted(name, global_writers, summaries) {
                return true;
            }
            match params.and_then(|p| Some((p, p.params.iter().position(|n| n == name)?))) {
                Some((p, idx)) => parameter_is_risky(p.func_name, idx, summaries, global_writers),
                None => false,
            }
        }
        "parenthesized_expression" => match op.named_child(0) {
            Some(inner) => operand_is_risky(
                &inner,
                risky_vars,
                summaries,
                global_writers,
                params,
                source,
            ),
            None => false,
        },
        "cast_expression" => match op.child_by_field_name("value") {
            Some(value) => operand_is_risky(
                &value,
                risky_vars,
                summaries,
                global_writers,
                params,
                source,
            ),
            None => false,
        },
        "binary_expression" => {
            op.child_by_field_name("left").is_some_and(|l| {
                operand_is_risky(&l, risky_vars, summaries, global_writers, params, source)
            }) || op.child_by_field_name("right").is_some_and(|r| {
                operand_is_risky(&r, risky_vars, summaries, global_writers, params, source)
            })
        }
        "unary_expression" | "update_expression" => match op.child_by_field_name("argument") {
            Some(arg) => {
                operand_is_risky(&arg, risky_vars, summaries, global_writers, params, source)
            }
            None => false,
        },
        // number_literal, field_expression, subscript_expression, etc. are
        // bounded local state — the dominant false-positive class.
        _ => false,
    }
}

/// True when `name` is a file-scope global written by at least one tainted
/// function (covers Juliet `_68`-style global-channel data flow and real
/// configuration globals fed from the environment).
fn global_is_tainted(
    name: &str,
    global_writers: &HashMap<String, HashSet<String>>,
    summaries: &(impl SummaryLookup + ?Sized),
) -> bool {
    match global_writers.get(name) {
        Some(ws) => ws.iter().any(|w| {
            matches!(summaries.get(w), Some(s) if s.has_env03_taint_source || s.returns_tainted)
        }),
        None => false,
    }
}
