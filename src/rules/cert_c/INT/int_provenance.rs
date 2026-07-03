//! Shared operand-provenance analysis for the INT overflow/wrap rules
//! (INT30-C unsigned wrap, INT32-C signed overflow).
//!
//! Implements the *opt-in* taint gate: an arithmetic operation is flagged only
//! when at least one operand derives from untrusted or unbounded input — a
//! taint source, a full-range parser, an untrusted-decode accessor, a
//! tainted-summary callee return, or a tainted global. Bounded local state
//! (loop counters, register/cursor indices, struct-field counts) is treated as
//! practically non-overflowing, which is what eliminates the bounded-counter
//! false positives that dominate hardened codebases.
//!
//! The rule-specific pieces (which VRA width to check, how to compute a
//! definite-overflow signal, the per-function memo) stay in each rule; this
//! module holds only the provenance classification, which is identical across
//! the signed and unsigned rules.

use crate::analyze::function_summary::FunctionSummary;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::std_functions;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// True when `callee` (any function-reference text) names a source of untrusted
/// or full-range values: a full-range integer parser (`atoi`/`strtol`/`rand`),
/// an untrusted-decode accessor (varint decoders — see
/// [`std_functions::is_untrusted_decode_function`]), a standard environment/IO
/// taint source (`scanf`/`recv`/`fgets`/...), or a project-local function whose
/// prescan summary carries taint (`has_env03_taint_source` directly or
/// `returns_tainted` transitively).
pub fn callee_is_risky_source(callee: &str, summaries: &HashMap<String, FunctionSummary>) -> bool {
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

/// Walk `body` ONCE and collect every variable name fed from a risky source:
///   - `var = riskyCall(...)` or `T var = riskyCall(...)` (return-value flow), or
///   - `riskySource(..., &var, ...)` / `riskySource(..., var, ...)` (fill by
///     reference, e.g. `fscanf(stdin, "%d", &data)`, `recv(fd, buf, ...)`).
///
/// Intended to be memoized per function by the caller, so this O(body) walk runs
/// once per function rather than once per arithmetic operand.
pub fn collect_risky_vars(
    body: &Node,
    summaries: &HashMap<String, FunctionSummary>,
    source: &str,
) -> HashSet<String> {
    let mut set = HashSet::new();
    collect_risky_vars_walk(body, summaries, source, &mut set);
    set
}

/// Classify a single operand subtree's provenance against the precomputed
/// risky-variable set. `global_writers` maps a global name to the functions that
/// write it; a global operand is risky when any writer carries taint.
pub fn operand_is_risky(
    op: &Node,
    risky_vars: &HashSet<String>,
    summaries: &HashMap<String, FunctionSummary>,
    global_writers: &HashMap<String, HashSet<String>>,
    source: &str,
) -> bool {
    match op.kind() {
        "call_expression" => match op.child_by_field_name("function") {
            Some(f) => callee_is_risky_source(&get_node_text(&f, source), summaries),
            None => false,
        },
        "identifier" => {
            let name = get_node_text(op, source);
            risky_vars.contains(name) || global_is_tainted(name, global_writers, summaries)
        }
        "parenthesized_expression" => match op.named_child(0) {
            Some(inner) => operand_is_risky(&inner, risky_vars, summaries, global_writers, source),
            None => false,
        },
        "cast_expression" => match op.child_by_field_name("value") {
            Some(value) => operand_is_risky(&value, risky_vars, summaries, global_writers, source),
            None => false,
        },
        "binary_expression" => {
            op.child_by_field_name("left").is_some_and(|l| {
                operand_is_risky(&l, risky_vars, summaries, global_writers, source)
            }) || op.child_by_field_name("right").is_some_and(|r| {
                operand_is_risky(&r, risky_vars, summaries, global_writers, source)
            })
        }
        "unary_expression" | "update_expression" => match op.child_by_field_name("argument") {
            Some(arg) => operand_is_risky(&arg, risky_vars, summaries, global_writers, source),
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
    summaries: &HashMap<String, FunctionSummary>,
) -> bool {
    match global_writers.get(name) {
        Some(ws) => ws.iter().any(|w| {
            matches!(summaries.get(w), Some(s) if s.has_env03_taint_source || s.returns_tainted)
        }),
        None => false,
    }
}

fn collect_risky_vars_walk(
    node: &Node,
    summaries: &HashMap<String, FunctionSummary>,
    source: &str,
    set: &mut HashSet<String>,
) {
    let candidates = query::find_descendants_of_kinds(
        *node,
        &[
            "assignment_expression",
            "init_declarator",
            "call_expression",
        ],
    );
    for node in candidates {
        match node.kind() {
            // var = riskyCall(...)
            "assignment_expression" => {
                if let (Some(lhs), Some(rhs)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    if lhs.kind() == "identifier" && rhs_is_risky_call(&rhs, summaries, source) {
                        set.insert(get_node_text(&lhs, source).trim().to_string());
                    }
                }
            }
            // T var = riskyCall(...)
            "init_declarator" => {
                if let (Some(decl), Some(value)) = (
                    node.child_by_field_name("declarator"),
                    node.child_by_field_name("value"),
                ) {
                    if rhs_is_risky_call(&value, summaries, source) {
                        if let Some(name) = init_declarator_name(&decl, source) {
                            set.insert(name);
                        }
                    }
                }
            }
            // riskySource(..., &var, ...) — fill by reference: any identifier
            // appearing in the argument list of a risky call is conservatively
            // treated as fed (covers scanf-into-&var and recv-into-buf).
            "call_expression" => {
                if let Some(f) = node.child_by_field_name("function") {
                    if callee_is_risky_source(&get_node_text(&f, source), summaries) {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            collect_arg_identifiers(&args, source, set);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Insert every identifier appearing in `args` into `set`.
fn collect_arg_identifiers(args: &Node, source: &str, set: &mut HashSet<String>) {
    for ident in query::find_descendants_of_kind(*args, "identifier") {
        set.insert(get_node_text(&ident, source).trim().to_string());
    }
}

/// Resolve the bare identifier inside a (possibly pointer/array-wrapped)
/// declarator.
fn init_declarator_name(decl: &Node, source: &str) -> Option<String> {
    let mut current = *decl;
    loop {
        if current.kind() == "identifier" || current.kind() == "field_identifier" {
            return Some(get_node_text(&current, source).trim().to_string());
        }
        match current.child_by_field_name("declarator") {
            Some(inner) => current = inner,
            None => return None,
        }
    }
}

/// True when `rhs`, after stripping casts/parens, is a call to a risky source.
fn rhs_is_risky_call(
    rhs: &Node,
    summaries: &HashMap<String, FunctionSummary>,
    source: &str,
) -> bool {
    let mut node = *rhs;
    loop {
        match node.kind() {
            "parenthesized_expression" => match node.named_child(0) {
                Some(inner) => node = inner,
                None => return false,
            },
            "cast_expression" => match node.child_by_field_name("value") {
                Some(value) => node = value,
                None => return false,
            },
            "call_expression" => {
                return match node.child_by_field_name("function") {
                    Some(f) => callee_is_risky_source(&get_node_text(&f, source), summaries),
                    None => false,
                };
            }
            _ => return false,
        }
    }
}
