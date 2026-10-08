//! Shared accessors for value-range analysis (VRA) results from rule code.
//!
//! Several rules (INT30/31/32/34-C, ARR30-C, ...) store per-function CFGs and
//! VRA results, then look up the variable ranges in effect at a particular
//! expression. This module centralizes the two lookup strategies that had been
//! copy-pasted across those rules:
//!
//! - [`var_ranges_replay_at`] replays the containing block's statements from
//!   its entry up to the expression (intra-block precision); used where the
//!   per-file macro map is available.
//! - [`var_ranges_entry_at`] reads the block-entry ranges directly, with no
//!   intra-block replay and no macro resolution.
//!
//! This is the consolidation point for FP-reduction work layered on top of VRA.

use crate::analyze::cfg::FunctionCfg;
use crate::analyze::const_eval::{MacroConstantMap, ValueRange, VarRangeMap};
use crate::analyze::value_range::{self, RangeAnalysisResult};
use crate::utility::cert_c::ast_utils;
use std::collections::HashMap;
use tree_sitter::Node;

/// Variable ranges in effect at `expr_node`, computed by replaying the
/// containing block's statements from its entry up to (but not including) the
/// expression. Delegates to [`value_range::get_all_var_ranges_at`], which also
/// handles single-block functions and intra-block assignments.
pub fn var_ranges_replay_at(
    function_cfgs: &HashMap<usize, FunctionCfg>,
    vra_results: &HashMap<usize, RangeAnalysisResult>,
    expr_node: &Node,
    source: &str,
    macros: &MacroConstantMap,
) -> Option<VarRangeMap> {
    if vra_results.is_empty() || function_cfgs.is_empty() {
        return None;
    }
    let func = ast_utils::find_containing_function(expr_node)?;
    let start_byte = func.start_byte();
    let cfg = function_cfgs.get(&start_byte)?;
    let vra = vra_results.get(&start_byte)?;
    let body = func.child_by_field_name("body")?;
    value_range::get_all_var_ranges_at(vra, cfg, &body, source, macros, expr_node.start_byte())
}

/// Variable ranges at `expr_node` read directly from the containing block's
/// entry ranges (no intra-block replay, no macro resolution). Matches the
/// historical inline lookup in ARR30-C / INT31-C: prefer statement-level
/// containment, falling back to block byte-range containment.
pub fn var_ranges_entry_at(
    function_cfgs: &HashMap<usize, FunctionCfg>,
    vra_results: &HashMap<usize, RangeAnalysisResult>,
    expr_node: &Node,
) -> Option<VarRangeMap> {
    if vra_results.is_empty() || function_cfgs.is_empty() {
        return None;
    }
    let func = ast_utils::find_containing_function(expr_node)?;
    let start_byte = func.start_byte();
    let cfg = function_cfgs.get(&start_byte)?;
    let vra = vra_results.get(&start_byte)?;
    let byte_offset = expr_node.start_byte();

    let block = cfg
        .blocks
        .iter()
        .find(|b| {
            b.statements
                .iter()
                .any(|&(s, e)| byte_offset >= s && byte_offset < e)
        })
        .or_else(|| {
            cfg.blocks.iter().find(|b| {
                b.byte_range.0 > 0 && byte_offset >= b.byte_range.0 && byte_offset < b.byte_range.1
            })
        })?;

    let entry = vra.block_entry_ranges.get(&block.id)?;
    let var_ranges: VarRangeMap = entry
        .iter()
        .map(|(name, typed)| (name.clone(), typed.range))
        .collect();
    if var_ranges.is_empty() {
        None
    } else {
        Some(var_ranges)
    }
}

/// The range a parameter entered its function with, read at `ident` (an
/// occurrence of `name`) where that range still holds: `ident` resolves to the
/// parameter, and nothing in the body assigns it, steps it or takes its
/// address -- the writes VRA itself models -- so every point of the body,
/// reachable under the entry facts or not, sees the parameter as it came in.
///
/// For a site [`var_ranges_entry_at`] has no ranges for: a block VRA proved
/// unreachable keeps no state. A closed caller set that always passes one
/// flag (`set_opt(t, i, YES)`) makes the callee's other arm unreachable, and
/// an index parameter's caller range is then still the answer there.
pub fn unwritten_param_entry_range(
    function_cfgs: &HashMap<usize, FunctionCfg>,
    vra_results: &HashMap<usize, RangeAnalysisResult>,
    ident: &Node,
    name: &str,
    source: &str,
) -> Option<ValueRange> {
    let func = ast_utils::find_containing_function(ident)?;
    let start_byte = func.start_byte();
    let cfg = function_cfgs.get(&start_byte)?;
    let vra = vra_results.get(&start_byte)?;
    if !matches!(
        ast_utils::resolve_identifier_binding(ident, name, source)?,
        ast_utils::IdentifierBinding::Parameter(_)
    ) {
        return None;
    }
    let body = func.child_by_field_name("body")?;
    if writes_name(&body, name, source) {
        return None;
    }
    vra.block_entry_ranges
        .get(&cfg.entry)?
        .get(name)
        .map(|typed| typed.range)
}

/// Whether anything under `node` assigns, steps or takes the address of an
/// identifier spelled `name`, whatever it resolves to: a shadowing local's
/// write counts too, which only ever withholds a range.
fn writes_name(node: &Node, name: &str, source: &str) -> bool {
    let target = match node.kind() {
        "assignment_expression" => node.child_by_field_name("left"),
        "update_expression" => node.child_by_field_name("argument"),
        "pointer_expression" if node.child(0).is_some_and(|op| op.kind() == "&") => {
            node.child_by_field_name("argument")
        }
        _ => None,
    };
    let mut target = target;
    while let Some(t) = target.filter(|t| t.kind() == "parenthesized_expression") {
        target = t.named_child(0);
    }
    if target
        .is_some_and(|t| t.kind() == "identifier" && ast_utils::get_node_text(&t, source) == name)
    {
        return true;
    }
    let mut cursor = node.walk();
    let found = node
        .children(&mut cursor)
        .any(|child| writes_name(&child, name, source));
    found
}

/// Whether VRA carries positive evidence that `var_name` can hold a negative
/// value where `expr_node` sits.
///
/// Three situations collapse to `false`: VRA has no range for the variable,
/// the range it does have is entirely non-negative, and the range is exactly
/// the representable band of a signed type. The last is the one worth
/// spelling out -- an unconstrained `int` parameter is indistinguishable from
/// one VRA learned nothing about, so reading its full band as "could be
/// negative" turns every signed-to-unsigned assignment into a finding. That is
/// what INT16-C's assignment cluster did, at 0 true positives in 279 labeled
/// instances.
///
/// This is deliberately the opposite default from a soundness-first check:
/// absent information suppresses rather than reports.
pub fn has_negative_value_evidence(
    function_cfgs: &HashMap<usize, FunctionCfg>,
    vra_results: &HashMap<usize, RangeAnalysisResult>,
    expr_node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    var_name: &str,
) -> bool {
    let Some(ranges) = var_ranges_replay_at(function_cfgs, vra_results, expr_node, source, macros)
    else {
        return false;
    };
    let Some(range) = ranges.get(var_name) else {
        return false;
    };
    range.min < 0 && !is_full_signed_band(range)
}

/// True when `range` is exactly the band some signed integer type can hold --
/// i.e. VRA converged on "anything of this type" and so proved nothing about
/// the value.
fn is_full_signed_band(range: &crate::analyze::const_eval::ValueRange) -> bool {
    matches!(
        (range.min, range.max),
        (-128, 127) | (-32768, 32767) | (-2147483648, 2147483647) | (i64::MIN, i64::MAX)
    )
}
