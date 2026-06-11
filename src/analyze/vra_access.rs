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
use crate::analyze::const_eval::{MacroConstantMap, VarRangeMap};
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
