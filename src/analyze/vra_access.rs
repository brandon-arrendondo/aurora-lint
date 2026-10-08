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
use crate::analyze::name_writes::NameScope;
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
/// parameter, and nothing in the body can write it (`NameScope::may_write`:
/// no assignment, step or address of it, and no name that could expand to
/// one), so every point of the body sees the parameter as it came in.
///
/// For a site where [`var_ranges_entry_at`] gives no range for the variable,
/// for whatever reason. One is a block VRA proved unreachable, which keeps
/// no state at all: a closed caller set
/// that always passes one flag (`set_opt(t, i, YES)`) makes the callee's
/// other arm unreachable, and an index parameter's caller range is then
/// still the answer there.
pub(crate) fn unwritten_param_entry_range(
    function_cfgs: &HashMap<usize, FunctionCfg>,
    vra_results: &HashMap<usize, RangeAnalysisResult>,
    ident: &Node,
    name: &str,
    source: &str,
    scope: &NameScope,
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
    // Any occurrence spelled `name` counts, a shadowing local's too, which
    // only ever withholds a range.
    let spelled =
        |n: &Node| n.kind() == "identifier" && ast_utils::get_node_text(n, source) == name;
    if scope.may_write(&body, source, name, &spelled, false) {
        return None;
    }
    vra.block_entry_ranges
        .get(&cfg.entry)?
        .get(name)
        .map(|typed| typed.range)
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
