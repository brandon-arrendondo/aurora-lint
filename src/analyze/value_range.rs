//! CFG-based forward value-range analysis.
//!
//! Computes integer value ranges for variables at every point in a function
//! using a worklist algorithm on the CFG. This replaces syntactic ancestor
//! walks (extract_loop_var_ranges, extract_if_condition_ranges) with proper
//! dataflow that handles sequential assignments, conditional narrowing through
//! arbitrary CFG paths, and early-return guard patterns.
//!
//! Follows the same forward-dataflow pattern as `null_state.rs`.
#![allow(dead_code)]

use super::cfg::{BasicBlock, BlockId, CfgEdge, FunctionCfg};
use super::const_eval::{self, MacroConstantMap, ValueRange, VarRangeMap};
use super::dataflow::find_node_at_range;
use super::function_summary::FunctionSummary;
use std::collections::{HashMap, HashSet, VecDeque};
use tree_sitter::Node;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Type information for a variable (signedness + bit width).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarType {
    /// Whether the type is signed.
    pub is_signed: bool,
    /// Bit width of the type (8/16/32/64).
    pub bit_width: u32,
}

impl VarType {
    /// Full range for this type.
    pub fn full_range(&self) -> ValueRange {
        if self.is_signed {
            match self.bit_width {
                8 => ValueRange::new(-128, 127),
                16 => ValueRange::new(-32768, 32767),
                32 => ValueRange::new(-2147483648, 2147483647),
                64 => ValueRange::new(i64::MIN, i64::MAX),
                _ => ValueRange::new(i64::MIN, i64::MAX),
            }
        } else {
            match self.bit_width {
                8 => ValueRange::new(0, 255),
                16 => ValueRange::new(0, 65535),
                32 => ValueRange::new(0, 4294967295),
                64 => ValueRange::new(0, i64::MAX), // best we can do with i64
                _ => ValueRange::new(0, i64::MAX),
            }
        }
    }
}

/// A value range with optional type information.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedRange {
    /// The value range itself.
    pub range: ValueRange,
    /// The variable's type, when known.
    pub var_type: Option<VarType>,
}

/// Per-variable range map for a single program point.
pub type RangeMap = HashMap<String, TypedRange>;

/// Result of value-range analysis for one function.
#[derive(Clone)]
pub struct RangeAnalysisResult {
    /// Entry ranges for each block (after joining predecessors + edge refinement).
    pub block_entry_ranges: HashMap<BlockId, RangeMap>,
    /// Exit ranges for each block (after transfer function).
    pub block_exit_ranges: HashMap<BlockId, RangeMap>,
    /// Callee return ranges used during analysis (retained for intra-block replay
    /// in `get_var_range_at` / `eval_expr_range_at`).
    pub(crate) return_ranges: HashMap<String, ValueRange>,
}

// ---------------------------------------------------------------------------
// Lattice operations
// ---------------------------------------------------------------------------

/// Join two ranges (interval hull): [min(a.min, b.min), max(a.max, b.max)].
fn join_range(a: &ValueRange, b: &ValueRange) -> ValueRange {
    ValueRange::new(a.min.min(b.min), a.max.max(b.max))
}

/// Intersect two ranges: [max(a.min, b.min), min(a.max, b.max)].
/// Returns None if the intersection is empty.
fn intersect_range(a: &ValueRange, b: &ValueRange) -> Option<ValueRange> {
    let min = a.min.max(b.min);
    let max = a.max.min(b.max);
    if min <= max {
        Some(ValueRange::new(min, max))
    } else {
        None
    }
}

/// Join two typed ranges, preserving type info if identical.
fn join_typed(a: &TypedRange, b: &TypedRange) -> TypedRange {
    TypedRange {
        range: join_range(&a.range, &b.range),
        var_type: if a.var_type == b.var_type {
            a.var_type.clone()
        } else {
            None
        },
    }
}

/// Join two range maps (union of keys, interval hull per key).
fn join_range_maps(a: &RangeMap, b: &RangeMap) -> RangeMap {
    let mut result = a.clone();
    for (var, tb) in b {
        let entry = result.entry(var.clone()).or_insert_with(|| tb.clone());
        if a.contains_key(var) {
            *entry = join_typed(entry, tb);
        }
    }
    result
}

/// Widen a range: if a dimension grew compared to the old range, push it to
/// the type bound (or i64 extremes if no type is known).
fn widen_typed(old: &TypedRange, new: &TypedRange) -> TypedRange {
    let type_range = old
        .var_type
        .as_ref()
        .map(|t| t.full_range())
        .unwrap_or(ValueRange::new(i64::MIN, i64::MAX));

    let min = if new.range.min < old.range.min {
        type_range.min
    } else {
        new.range.min
    };
    let max = if new.range.max > old.range.max {
        type_range.max
    } else {
        new.range.max
    };

    TypedRange {
        range: ValueRange::new(min, max),
        var_type: old.var_type.clone(),
    }
}

// ---------------------------------------------------------------------------
// Type extraction from AST
// ---------------------------------------------------------------------------

/// Extract type info from a declaration node's type specifiers.
fn extract_var_type_from_declaration(decl_node: &Node, source: &str) -> Option<VarType> {
    let mut is_unsigned = false;
    let mut is_signed = false;
    let mut base_type: Option<String> = None;

    for i in 0..decl_node.child_count() {
        if let Some(child) = decl_node.child(i) {
            match child.kind() {
                "type_qualifier" => {
                    // const, volatile — doesn't affect range
                }
                "primitive_type" => {
                    let text = child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    base_type = Some(text);
                }
                "sized_type_specifier" => {
                    let text = child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    // e.g. "unsigned int", "signed long long", "unsigned char"
                    if text.contains("unsigned") {
                        is_unsigned = true;
                    }
                    if text.contains("signed") && !text.contains("unsigned") {
                        is_signed = true;
                    }
                    base_type = Some(text);
                }
                _ => {}
            }
        }
    }

    let type_text = base_type?;
    let t = type_text.trim();

    // Determine signedness and bit width
    let (signed, bits) = match t {
        "char" | "signed char" => (true, 8u32),
        "unsigned char" => (false, 8),
        "short" | "short int" | "signed short" | "signed short int" => (true, 16),
        "unsigned short" | "unsigned short int" => (false, 16),
        "int" | "signed" | "signed int" => (true, 32),
        "unsigned" | "unsigned int" => (false, 32),
        "long" | "long int" | "signed long" | "signed long int" => (true, 64),
        "unsigned long" | "unsigned long int" => (false, 64),
        "long long" | "long long int" | "signed long long" | "signed long long int" => (true, 64),
        "unsigned long long" | "unsigned long long int" => (false, 64),
        _ => {
            // Typedef names
            if t.starts_with("uint") || t.starts_with("size_t") {
                let bits = if t.contains("8") {
                    8
                } else if t.contains("16") {
                    16
                } else if t.contains("32") {
                    32
                } else {
                    64
                };
                (false, bits)
            } else if t.starts_with("int") && t.ends_with("_t") {
                let bits = if t.contains("8") {
                    8
                } else if t.contains("16") {
                    16
                } else if t.contains("32") {
                    32
                } else {
                    64
                };
                (true, bits)
            } else {
                // Unknown type: assume signed 32
                // Check explicit unsigned/signed keywords
                if is_unsigned {
                    (false, 32)
                } else if is_signed {
                    (true, 32)
                } else {
                    return None;
                }
            }
        }
    };

    Some(VarType {
        is_signed: signed,
        bit_width: bits,
    })
}

/// Infer type from a cast expression's type descriptor.
fn extract_cast_type(cast_node: &Node, source: &str) -> Option<VarType> {
    let type_desc = cast_node.child_by_field_name("type")?;
    let text = type_desc
        .utf8_text(source.as_bytes())
        .ok()?
        .trim()
        .to_string();

    let (signed, bits) = match text.as_str() {
        "char" | "signed char" | "int8_t" => (true, 8u32),
        "unsigned char" | "uint8_t" => (false, 8),
        "short" | "signed short" | "int16_t" => (true, 16),
        "unsigned short" | "uint16_t" => (false, 16),
        "int" | "signed int" | "int32_t" => (true, 32),
        "unsigned int" | "unsigned" | "uint32_t" => (false, 32),
        "long" | "long int" | "int64_t" | "long long" => (true, 64),
        "unsigned long" | "size_t" | "uint64_t" | "unsigned long long" => (false, 64),
        _ => return None,
    };
    Some(VarType {
        is_signed: signed,
        bit_width: bits,
    })
}

// ---------------------------------------------------------------------------
// Transfer function
// ---------------------------------------------------------------------------

/// Apply the transfer function for a single block: walk its statements and
/// update variable ranges.
fn apply_range_transfer(
    block: &BasicBlock,
    entry: &RangeMap,
    body: &Node,
    source: &str,
    macros: &MacroConstantMap,
    summaries: &HashMap<String, FunctionSummary>,
    local_types: &HashMap<String, VarType>,
) -> RangeMap {
    let mut state = entry.clone();
    for &(start, end) in &block.statements {
        if let Some(stmt_node) = find_node_at_range(body, start, end) {
            process_statement_for_ranges(
                &stmt_node,
                source,
                macros,
                summaries,
                &mut state,
                local_types,
            );
        }
    }
    state
}

/// Process a single statement, updating the range map.
fn process_statement_for_ranges(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    summaries: &HashMap<String, FunctionSummary>,
    state: &mut RangeMap,
    local_types: &HashMap<String, VarType>,
) {
    match node.kind() {
        "declaration" => {
            process_declaration_range(node, source, macros, summaries, state);
        }
        "expression_statement" => {
            if let Some(expr) = node.child(0) {
                process_expression_range(&expr, source, macros, summaries, state, local_types);
            }
        }
        "switch_statement" => {
            // The CFG lowers a switch to a single opaque statement, so its
            // internal control flow is unmodeled: any contained modification
            // may or may not execute on a given path.
            process_opaque_region(node, source, macros, summaries, state, local_types);
        }
        _ => {
            // Recurse for nested assignments
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "assignment_expression"
                        || child.kind() == "update_expression"
                    {
                        process_expression_range(
                            &child,
                            source,
                            macros,
                            summaries,
                            state,
                            local_types,
                        );
                    }
                }
            }
        }
    }
}

/// Conservatively account for variable modifications inside a region whose
/// internal control flow is not modeled by the CFG (e.g. a switch body).
/// Assignments join their RHS with the current range (the path may or may
/// not execute); increments, compound assignments, and `&var` call arguments
/// widen the variable to its full type range.
fn process_opaque_region(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    summaries: &HashMap<String, FunctionSummary>,
    state: &mut RangeMap,
    local_types: &HashMap<String, VarType>,
) {
    let widen = |state: &mut RangeMap, var_name: String| {
        let var_type = state
            .get(&var_name)
            .and_then(|c| c.var_type.clone())
            .or_else(|| local_types.get(&var_name).cloned());
        let range = var_type
            .as_ref()
            .map(|t| t.full_range())
            .unwrap_or(ValueRange::new(i64::MIN, i64::MAX));
        state.insert(var_name, TypedRange { range, var_type });
    };

    match node.kind() {
        "assignment_expression" => {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                if left.kind() == "identifier" {
                    let var_name = get_text(&left, source);
                    let op = get_assignment_operator(node, source);
                    let rhs_range = if op == "=" {
                        let var_ranges = extract_var_ranges_from_state(state);
                        const_eval::try_evaluate_range(&right, source, macros, &var_ranges)
                            .or_else(|| resolve_call_return_range(&right, source, summaries))
                    } else {
                        None // compound assignment: treat as unknown
                    };
                    match rhs_range {
                        Some(r) => {
                            let cur = state.get(&var_name);
                            let var_type = cur
                                .and_then(|c| c.var_type.clone())
                                .or_else(|| local_types.get(&var_name).cloned());
                            let joined = match cur {
                                Some(c) => join_range(&c.range, &r),
                                None => r,
                            };
                            let range = if let Some(vt) = &var_type {
                                apply_unsigned_wrapping(joined, vt)
                            } else {
                                joined
                            };
                            state.insert(var_name, TypedRange { range, var_type });
                        }
                        None => widen(state, var_name),
                    }
                }
            }
        }
        "update_expression" => {
            if let Some(arg) = node.child_by_field_name("argument") {
                if arg.kind() == "identifier" {
                    widen(state, get_text(&arg, source));
                }
            }
        }
        "call_expression" => {
            // Reuse the `&var` argument widening from the exact transfer.
            process_expression_range(node, source, macros, summaries, state, local_types);
        }
        _ => {}
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            process_opaque_region(&child, source, macros, summaries, state, local_types);
        }
    }
}

/// Wrap a VRA range to fit an unsigned type's actual representation.
///
/// C converts negative signed integer literals to unsigned by wrapping:
/// `unsigned int x = -2` stores `UINT_MAX - 1 = 4294967294`, not -2.
/// VRA evaluates the literal as -2 (signed), then stores it without
/// conversion — so downstream checks see a negative range for an unsigned
/// variable and produce false positives.
///
/// Handles the common all-negative-range case (e.g., `data = -2`).
/// Mixed ranges (spanning 0) are widened to the full unsigned type range.
fn apply_unsigned_wrapping(range: ValueRange, vt: &VarType) -> ValueRange {
    if vt.is_signed || range.min >= 0 {
        return range;
    }
    if vt.bit_width >= 64 {
        // Can't represent wrapped value in i64 (UINT64_MAX overflows).
        // Return full unsigned 64-bit range as representable in i64.
        return ValueRange::new(0, i64::MAX);
    }
    let modulus = 1i64 << vt.bit_width;
    if range.max < 0 {
        // All values negative: wrapping is monotone, preserves order.
        let wrapped_min = ((range.min % modulus) + modulus) % modulus;
        let wrapped_max = ((range.max % modulus) + modulus) % modulus;
        ValueRange::new(wrapped_min, wrapped_max)
    } else {
        // Mixed: negative..non-negative — use full unsigned type range.
        vt.full_range()
    }
}

/// Process a declaration, extracting type and initial value range.
fn process_declaration_range(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    summaries: &HashMap<String, FunctionSummary>,
    state: &mut RangeMap,
) {
    let var_type = extract_var_type_from_declaration(node, source);

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "init_declarator" {
                if let Some(declarator) = child.child_by_field_name("declarator") {
                    let var_name = get_declarator_name(&declarator, source);
                    if var_name.is_empty() {
                        continue;
                    }
                    // Skip pointer/array declarators — we track integer ranges only
                    if is_pointer_or_array(&declarator) {
                        continue;
                    }

                    if let Some(value) = child.child_by_field_name("value") {
                        // Has initializer: try to evaluate it
                        let var_ranges = extract_var_ranges_from_state(state);
                        if let Some(raw_range) =
                            const_eval::try_evaluate_range(&value, source, macros, &var_ranges)
                        {
                            let range = if let Some(vt) = &var_type {
                                apply_unsigned_wrapping(raw_range, vt)
                            } else {
                                raw_range
                            };
                            state.insert(
                                var_name,
                                TypedRange {
                                    range,
                                    var_type: var_type.clone(),
                                },
                            );
                        } else if let Some(range) =
                            resolve_call_return_range(&value, source, summaries)
                        {
                            state.insert(
                                var_name,
                                TypedRange {
                                    range,
                                    var_type: var_type.clone(),
                                },
                            );
                        } else {
                            // Can't evaluate — use type range
                            let range = var_type
                                .as_ref()
                                .map(|t| t.full_range())
                                .unwrap_or(ValueRange::new(i64::MIN, i64::MAX));
                            state.insert(
                                var_name,
                                TypedRange {
                                    range,
                                    var_type: var_type.clone(),
                                },
                            );
                        }
                    } else {
                        // Uninitialized — use full type range
                        let range = var_type
                            .as_ref()
                            .map(|t| t.full_range())
                            .unwrap_or(ValueRange::new(i64::MIN, i64::MAX));
                        state.insert(
                            var_name,
                            TypedRange {
                                range,
                                var_type: var_type.clone(),
                            },
                        );
                    }
                }
            } else if is_plain_declarator(child.kind()) {
                // Plain declarator without initializer: `unsigned int data;`
                // tree-sitter C emits just an `identifier` (or `array_declarator`,
                // `pointer_declarator`, etc.) as a direct child of the declaration.
                let var_name = get_declarator_name(&child, source);
                if var_name.is_empty() || is_pointer_or_array(&child) {
                    continue;
                }
                let range = var_type
                    .as_ref()
                    .map(|t| t.full_range())
                    .unwrap_or(ValueRange::new(i64::MIN, i64::MAX));
                state.insert(
                    var_name,
                    TypedRange {
                        range,
                        var_type: var_type.clone(),
                    },
                );
            }
        }
    }
}

/// Returns true if this node kind represents a plain (non-initialized) declarator
/// that is a direct child of a declaration node.
fn is_plain_declarator(kind: &str) -> bool {
    matches!(
        kind,
        "identifier" | "array_declarator" | "pointer_declarator" | "function_declarator"
    )
}

/// Process an expression that may update ranges (assignments, increments).
fn process_expression_range(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    summaries: &HashMap<String, FunctionSummary>,
    state: &mut RangeMap,
    local_types: &HashMap<String, VarType>,
) {
    match node.kind() {
        "assignment_expression" => {
            process_assignment_range(node, source, macros, summaries, state, local_types)
        }
        "update_expression" => process_update_range(node, source, state),
        "call_expression" => process_call_arg_widening_range(node, source, state),
        _ => {}
    }
}

/// `"assignment_expression"` case of [`process_expression_range`]: dispatch
/// on the assignment operator once the LHS is confirmed to be a plain
/// identifier.
fn process_assignment_range(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    summaries: &HashMap<String, FunctionSummary>,
    state: &mut RangeMap,
    local_types: &HashMap<String, VarType>,
) {
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    if left.kind() != "identifier" {
        return;
    }
    let var_name = get_text(&left, source);
    let op = get_assignment_operator(node, source);
    let var_ranges = extract_var_ranges_from_state(state);

    match op.as_str() {
        "=" => process_simple_assignment_range(
            &var_name,
            &right,
            source,
            macros,
            summaries,
            state,
            local_types,
            &var_ranges,
        ),
        "+=" | "-=" | "*=" | "<<=" | ">>=" => process_compound_assignment_range(
            &var_name,
            &op,
            &right,
            source,
            macros,
            state,
            &var_ranges,
        ),
        _ => {}
    }
}

/// `var = expr` case: evaluate the RHS as a constant range, else resolve a
/// known callee's return range, else widen to the variable's full type
/// range (can't evaluate — conservative fallback).
fn process_simple_assignment_range(
    var_name: &str,
    right: &Node,
    source: &str,
    macros: &MacroConstantMap,
    summaries: &HashMap<String, FunctionSummary>,
    state: &mut RangeMap,
    local_types: &HashMap<String, VarType>,
    var_ranges: &VarRangeMap,
) {
    if let Some(raw_range) = const_eval::try_evaluate_range(right, source, macros, var_ranges) {
        let var_type = state.get(var_name).and_then(|t| t.var_type.clone());
        let range = match &var_type {
            Some(vt) => apply_unsigned_wrapping(raw_range, vt),
            None => raw_range,
        };
        state.insert(var_name.to_string(), TypedRange { range, var_type });
        return;
    }
    if let Some(range) = resolve_call_return_range(right, source, summaries) {
        let var_type = state.get(var_name).and_then(|t| t.var_type.clone());
        state.insert(var_name.to_string(), TypedRange { range, var_type });
        return;
    }
    // Can't evaluate RHS — widen to type range.
    // Look up type from existing state first, then fall back to
    // local_types (for `int data;` without init).
    let existing = state.get(var_name);
    let var_type = existing
        .and_then(|e| e.var_type.clone())
        .or_else(|| local_types.get(var_name).cloned());
    let type_range = var_type
        .as_ref()
        .map(|t| t.full_range())
        .unwrap_or(ValueRange::new(i64::MIN, i64::MAX));
    state.insert(
        var_name.to_string(),
        TypedRange {
            range: type_range,
            var_type,
        },
    );
}

/// `var += expr` (and `-=`/`*=`/`<<=`/`>>=`) case: only updates state when
/// both the current range and an evaluable RHS range are available.
fn process_compound_assignment_range(
    var_name: &str,
    op: &str,
    right: &Node,
    source: &str,
    macros: &MacroConstantMap,
    state: &mut RangeMap,
    var_ranges: &VarRangeMap,
) {
    let Some(cur) = state.get(var_name) else {
        return;
    };
    let Some(rhs_range) = const_eval::try_evaluate_range(right, source, macros, var_ranges) else {
        return;
    };
    let new_range = match op {
        "+=" => cur.range.add(&rhs_range),
        "-=" => cur.range.sub(&rhs_range),
        "*=" => cur.range.mul(&rhs_range),
        "<<=" => cur.range.shl(&rhs_range),
        _ => None,
    };
    if let Some(range) = new_range {
        let var_type = cur.var_type.clone();
        state.insert(var_name.to_string(), TypedRange { range, var_type });
    }
}

/// `"update_expression"` case of [`process_expression_range`]: `x++` / `x--`
/// / `++x` / `--x`.
fn process_update_range(node: &Node, source: &str, state: &mut RangeMap) {
    let (var_node, op_text) = get_update_info(node, source);
    let Some(var_name) = var_node else { return };
    let Some(cur) = state.get(&var_name) else {
        return;
    };
    let delta = if op_text == "++" {
        ValueRange::exact(1)
    } else {
        ValueRange::exact(-1)
    };
    if let Some(range) = cur.range.add(&delta) {
        let var_type = cur.var_type.clone();
        state.insert(var_name, TypedRange { range, var_type });
    }
}

/// `"call_expression"` case of [`process_expression_range`]: any variable
/// passed as `&var` may be written to by the callee, so widen it to its
/// full type range (conservative).
fn process_call_arg_widening_range(node: &Node, source: &str, state: &mut RangeMap) {
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    for i in 0..args.child_count() {
        let Some(arg) = args.child(i) else { continue };
        if arg.kind() != "pointer_expression" && arg.kind() != "unary_expression" {
            continue;
        }
        // Find the identifier inside &identifier
        for j in 0..arg.child_count() {
            let Some(inner) = arg.child(j) else { continue };
            if inner.kind() != "identifier" {
                continue;
            }
            let var_name = get_text(&inner, source);
            if let Some(existing) = state.get(&var_name) {
                let var_type = existing.var_type.clone();
                let full_range = var_type
                    .as_ref()
                    .map(|t| t.full_range())
                    .unwrap_or(ValueRange::new(i64::MIN, i64::MAX));
                state.insert(
                    var_name,
                    TypedRange {
                        range: full_range,
                        var_type,
                    },
                );
            }
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Edge refinement
// ---------------------------------------------------------------------------

/// Information extracted from a condition for range edge refinement.
struct RangeConditionInfo {
    var_name: String,
    true_range: Option<ValueRange>,
    false_range: Option<ValueRange>,
}

/// Return true if this branch edge is provably dead because the predecessor's
/// condition evaluates to a compile-time constant that contradicts the edge
/// direction. Uses only macro/literal evaluation (empty VarRangeMap) so that
/// only genuine compile-time constants (e.g. `if(1)`, `if(staticTrue)`) are
/// pruned, not runtime-narrowed ranges.
fn is_dead_constant_edge(
    pred_id: BlockId,
    edge_kind: &CfgEdge,
    cfg: &FunctionCfg,
    body: &Node,
    source: &str,
    macros: &MacroConstantMap,
) -> bool {
    let is_true = matches!(edge_kind, CfgEdge::TrueBranch);
    let is_false = matches!(edge_kind, CfgEdge::FalseBranch);
    if !is_true && !is_false {
        return false;
    }
    let pred_block = match cfg.get_block(pred_id) {
        Some(b) => b,
        None => return false,
    };
    let (cond_start, cond_end) = match pred_block.condition_range {
        Some(r) => r,
        None => return false,
    };
    let cond_node = match find_node_at_range(body, cond_start, cond_end) {
        Some(n) => n,
        None => return false,
    };
    // Evaluate with empty var-ranges: only compile-time constants are resolved
    let empty = VarRangeMap::new();
    if let Some(val) = const_eval::try_evaluate_range(&cond_node, source, macros, &empty) {
        // Only act on definite constants (min == max)
        if val.min == val.max {
            let c = val.min;
            if is_true && c == 0 {
                return true; // always-false condition → true branch never taken
            }
            if is_false && c != 0 {
                return true; // always-true condition → false branch never taken
            }
        }
    }
    false
}

/// Apply edge refinement: given a predecessor's exit ranges and the edge type,
/// refine ranges based on the predecessor's condition.
fn apply_range_edge_refinement(
    pred_exit: &RangeMap,
    pred_id: BlockId,
    edge_kind: &CfgEdge,
    cfg: &FunctionCfg,
    body: &Node,
    source: &str,
    macros: &MacroConstantMap,
) -> RangeMap {
    let mut state = pred_exit.clone();

    let is_true = matches!(edge_kind, CfgEdge::TrueBranch);
    let is_false = matches!(edge_kind, CfgEdge::FalseBranch);
    if !is_true && !is_false {
        return state;
    }

    let pred_block = match cfg.get_block(pred_id) {
        Some(b) => b,
        None => return state,
    };
    let (cond_start, cond_end) = match pred_block.condition_range {
        Some(r) => r,
        None => return state,
    };

    let cond_node = match find_node_at_range(body, cond_start, cond_end) {
        Some(n) => n,
        None => return state,
    };

    let infos = parse_range_conditions(&cond_node, source, macros, &state);

    for info in &infos {
        let refinement = if is_true {
            &info.true_range
        } else {
            &info.false_range
        };

        if let Some(ref_range) = refinement {
            if let Some(existing) = state.get(&info.var_name) {
                if let Some(narrowed) = intersect_range(&existing.range, ref_range) {
                    let mut updated = existing.clone();
                    updated.range = narrowed;
                    state.insert(info.var_name.clone(), updated);
                }
                // If intersection is empty, keep the existing range (shouldn't
                // happen in well-formed code, but be conservative).
            }
        }
    }

    state
}

/// Parse a condition AST node and extract range refinement info for all
/// variables mentioned in comparisons.
fn parse_range_conditions(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    state: &RangeMap,
) -> Vec<RangeConditionInfo> {
    match node.kind() {
        "parenthesized_expression" => {
            if let Some(inner) = node.child(1) {
                return parse_range_conditions(&inner, source, macros, state);
            }
            Vec::new()
        }
        "binary_expression" => {
            let op = get_operator_text(node, source);
            match op.as_str() {
                "&&" => {
                    // A && B: true = intersect(A.true, B.true), false = join(A.false, B.false)
                    let left = node.child_by_field_name("left");
                    let right = node.child_by_field_name("right");
                    let left_infos = left
                        .map(|l| parse_range_conditions(&l, source, macros, state))
                        .unwrap_or_default();
                    let right_infos = right
                        .map(|r| parse_range_conditions(&r, source, macros, state))
                        .unwrap_or_default();

                    merge_compound_conditions(&left_infos, &right_infos, true)
                }
                "||" => {
                    // A || B: true = join(A.true, B.true), false = intersect(A.false, B.false)
                    let left = node.child_by_field_name("left");
                    let right = node.child_by_field_name("right");
                    let left_infos = left
                        .map(|l| parse_range_conditions(&l, source, macros, state))
                        .unwrap_or_default();
                    let right_infos = right
                        .map(|r| parse_range_conditions(&r, source, macros, state))
                        .unwrap_or_default();

                    merge_compound_conditions(&left_infos, &right_infos, false)
                }
                "<" | "<=" | ">" | ">=" | "==" | "!=" => {
                    parse_comparison_condition(node, source, macros, state)
                }
                _ => Vec::new(),
            }
        }
        "unary_expression" => {
            // Handle !expr
            let op = node
                .child_by_field_name("operator")
                .or_else(|| node.child(0));
            if let Some(op_node) = op {
                if get_text(&op_node, source) == "!" {
                    if let Some(arg) = node
                        .child_by_field_name("argument")
                        .or_else(|| node.child(1))
                    {
                        // Negate: swap true/false ranges
                        let inner = parse_range_conditions(&arg, source, macros, state);
                        return inner
                            .into_iter()
                            .map(|info| RangeConditionInfo {
                                var_name: info.var_name,
                                true_range: info.false_range,
                                false_range: info.true_range,
                            })
                            .collect();
                    }
                }
            }
            Vec::new()
        }
        "identifier" => {
            // Bare `if (x)` — means x != 0
            let var_name = get_text(node, source);
            if state.contains_key(&var_name) {
                let existing = &state[&var_name].range;
                // True branch: x != 0
                let true_range = if existing.min == 0 {
                    Some(ValueRange::new(1, existing.max))
                } else {
                    Some(*existing)
                };
                // False branch: x == 0
                let false_range = Some(ValueRange::exact(0));
                vec![RangeConditionInfo {
                    var_name,
                    true_range,
                    false_range,
                }]
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

/// Parse a single comparison (e.g. `x < N`, `x == 0`, `x != 0`).
fn parse_comparison_condition(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    state: &RangeMap,
) -> Vec<RangeConditionInfo> {
    let left = match node.child_by_field_name("left") {
        Some(n) => n,
        None => return Vec::new(),
    };
    let right = match node.child_by_field_name("right") {
        Some(n) => n,
        None => return Vec::new(),
    };
    let op = get_operator_text(node, source);

    let var_ranges = extract_var_ranges_from_state(state);

    // Try both orientations: var OP const and const OP var
    let mut results = Vec::new();

    // Case 1: identifier on left, evaluable expression on right
    if let Some(var_name) = extract_simple_var(&left, source) {
        if let Some(bound) = const_eval::try_evaluate_range(&right, source, macros, &var_ranges) {
            if let Some(info) = make_comparison_info(var_name, &op, bound, state, false) {
                results.push(info);
            }
        }
    }

    // Case 2: evaluable expression on left, identifier on right (reversed)
    if let Some(var_name) = extract_simple_var(&right, source) {
        if let Some(bound) = const_eval::try_evaluate_range(&left, source, macros, &var_ranges) {
            // Reverse the operator
            let rev_op = match op.as_str() {
                "<" => ">",
                "<=" => ">=",
                ">" => "<",
                ">=" => "<=",
                other => other, // == and != are symmetric
            };
            if let Some(info) = make_comparison_info(var_name, rev_op, bound, state, false) {
                results.push(info);
            }
        }
    }

    results
}

/// Build a RangeConditionInfo from a comparison `var OP bound`.
fn make_comparison_info(
    var_name: String,
    op: &str,
    bound: ValueRange,
    state: &RangeMap,
    _reversed: bool,
) -> Option<RangeConditionInfo> {
    // We use bound.min for single-value bounds and bound.max for range bounds.
    // For exact comparisons (== N), bound should be exact (min == max).
    let existing = state.get(&var_name).map(|t| &t.range);
    let full = existing
        .copied()
        .unwrap_or(ValueRange::new(i64::MIN, i64::MAX));

    match op {
        "<" => {
            // x < N: true => x.max = min(x.max, N-1), false => x.min = max(x.min, N)
            let n = bound.min; // use lower bound for safety
            Some(RangeConditionInfo {
                var_name,
                true_range: Some(ValueRange::new(full.min, full.max.min(n.saturating_sub(1)))),
                false_range: Some(ValueRange::new(full.min.max(n), full.max)),
            })
        }
        "<=" => {
            let n = bound.min;
            Some(RangeConditionInfo {
                var_name,
                true_range: Some(ValueRange::new(full.min, full.max.min(n))),
                false_range: Some(ValueRange::new(full.min.max(n.saturating_add(1)), full.max)),
            })
        }
        ">" => {
            let n = bound.max; // use upper bound for safety
            Some(RangeConditionInfo {
                var_name,
                true_range: Some(ValueRange::new(full.min.max(n.saturating_add(1)), full.max)),
                false_range: Some(ValueRange::new(full.min, full.max.min(n))),
            })
        }
        ">=" => {
            let n = bound.max;
            Some(RangeConditionInfo {
                var_name,
                true_range: Some(ValueRange::new(full.min.max(n), full.max)),
                false_range: Some(ValueRange::new(full.min, full.max.min(n.saturating_sub(1)))),
            })
        }
        "==" => {
            // x == N: true => [N, N]
            // false (fall-through) => x != N — mirror the != true_range narrowing.
            // When N sits at one endpoint of x's existing range (or N==0 for
            // non-negative x) we can produce a tight single-interval bound;
            // otherwise we conservatively return full (gap is non-contiguous).
            if bound.min == bound.max {
                let n = bound.min;
                let false_range = if n == 0 && full.min == 0 {
                    // x in [0, max] and x != 0 => x in [1, max]
                    Some(ValueRange::new(1, full.max))
                } else if n == 0 && full.max == 0 {
                    // x in [min, 0] and x != 0 => x in [min, -1]
                    Some(ValueRange::new(full.min, -1))
                } else if n == full.min {
                    // N is the lower endpoint => x in [N+1, max]
                    Some(ValueRange::new(n.saturating_add(1), full.max))
                } else if n == full.max {
                    // N is the upper endpoint => x in [min, N-1]
                    Some(ValueRange::new(full.min, n.saturating_sub(1)))
                } else {
                    Some(full) // N in interior; non-contiguous gap
                };
                Some(RangeConditionInfo {
                    var_name,
                    true_range: Some(bound),
                    false_range,
                })
            } else {
                None
            }
        }
        "!=" => {
            if bound.min == bound.max {
                let n = bound.min;
                // x != 0 is special: can tighten min from 0 to 1 when positive
                let false_range = Some(ValueRange::exact(n));
                let true_range = if n == 0 && full.min == 0 {
                    // x != 0 and x was [0, max] => x in [1, max]
                    Some(ValueRange::new(1, full.max))
                } else if n == 0 && full.max == 0 {
                    // x != 0 and x was [min, 0] => x in [min, -1]
                    Some(ValueRange::new(full.min, -1))
                } else if n == full.min {
                    Some(ValueRange::new(n.saturating_add(1), full.max))
                } else if n == full.max {
                    Some(ValueRange::new(full.min, n.saturating_sub(1)))
                } else {
                    Some(full) // Can't represent gap
                };
                Some(RangeConditionInfo {
                    var_name,
                    true_range,
                    false_range,
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Merge compound conditions (A && B or A || B).
/// For &&: true = intersect per-var true ranges; false = join per-var false ranges
/// For ||: true = join per-var true ranges; false = intersect per-var false ranges
fn merge_compound_conditions(
    left: &[RangeConditionInfo],
    right: &[RangeConditionInfo],
    is_and: bool,
) -> Vec<RangeConditionInfo> {
    let mut by_var: HashMap<String, (Option<ValueRange>, Option<ValueRange>)> = HashMap::new();

    // Collect all from left
    for info in left {
        let entry = by_var.entry(info.var_name.clone()).or_insert((None, None));
        entry.0 = info.true_range;
        entry.1 = info.false_range;
    }

    // Merge with right
    for info in right {
        let entry = by_var.entry(info.var_name.clone()).or_insert((None, None));

        if is_and {
            // &&: true = intersect, false = join
            entry.0 = match (entry.0, info.true_range) {
                (Some(a), Some(b)) => intersect_range(&a, &b),
                (Some(a), None) => Some(a),
                (None, b) => b,
            };
            entry.1 = match (entry.1, info.false_range) {
                (Some(a), Some(b)) => Some(join_range(&a, &b)),
                (Some(a), None) => Some(a),
                (None, b) => b,
            };
        } else {
            // ||: true = join, false = intersect
            entry.0 = match (entry.0, info.true_range) {
                (Some(a), Some(b)) => Some(join_range(&a, &b)),
                (Some(a), None) => Some(a),
                (None, b) => b,
            };
            entry.1 = match (entry.1, info.false_range) {
                (Some(a), Some(b)) => intersect_range(&a, &b),
                (Some(a), None) => Some(a),
                (None, b) => b,
            };
        }
    }

    by_var
        .into_iter()
        .map(|(var_name, (true_range, false_range))| RangeConditionInfo {
            var_name,
            true_range,
            false_range,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Main analysis
// ---------------------------------------------------------------------------

/// Maximum CFG blocks before skipping VRA to avoid O(N²) worst-case on huge functions.
const VRA_BLOCK_LIMIT: usize = 150;

/// Run forward value-range analysis on a function CFG. Returns an empty
/// result without analyzing when `cfg` exceeds [`VRA_BLOCK_LIMIT`] blocks.
pub fn analyze_value_ranges(
    cfg: &FunctionCfg,
    func_node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    summaries: &HashMap<String, FunctionSummary>,
) -> RangeAnalysisResult {
    // Skip VRA for very large functions to bound worst-case runtime.
    if cfg.blocks.len() > VRA_BLOCK_LIMIT {
        return empty_range_result();
    }

    let body = match func_node.child_by_field_name("body") {
        Some(b) => b,
        None => return empty_range_result(),
    };

    let initial_state = build_initial_state(func_node, source, summaries);

    // Collect types for uninitialized local declarations (e.g. `int data;`).
    // These are NOT added to the initial state (would cause stale entry ranges),
    // but passed as a fallback type lookup so that assignments like `data = atoi()`
    // use [INT_MIN, INT_MAX] instead of [i64::MIN, i64::MAX].
    let mut local_types: HashMap<String, VarType> = HashMap::new();
    collect_local_decl_types(&body, source, &mut local_types);

    let mut entry_ranges: HashMap<BlockId, RangeMap> = HashMap::new();
    let mut exit_ranges: HashMap<BlockId, RangeMap> = HashMap::new();

    // Initialize all blocks
    for block in &cfg.blocks {
        entry_ranges.insert(block.id, RangeMap::new());
        exit_ranges.insert(block.id, RangeMap::new());
    }

    // Entry block gets initial state
    entry_ranges.insert(cfg.entry, initial_state.clone());
    let entry_exit = apply_range_transfer(
        &cfg.blocks[cfg.entry],
        &initial_state,
        &body,
        source,
        macros,
        summaries,
        &local_types,
    );
    exit_ranges.insert(cfg.entry, entry_exit);

    // Worklist — companion set for O(1) membership test instead of O(N) VecDeque::contains.
    let mut worklist: VecDeque<BlockId> = VecDeque::new();
    let mut in_worklist: HashSet<BlockId> = HashSet::new();
    for (succ, _) in cfg.successors(cfg.entry) {
        worklist.push_back(succ);
        in_worklist.insert(succ);
    }

    // Track iteration counts per block for widening
    let mut block_iterations: HashMap<BlockId, usize> = HashMap::new();
    // Track which blocks are back-edge targets
    let back_edge_targets: HashSet<BlockId> = cfg
        .edges
        .iter()
        .filter(|(_, _, e)| matches!(e, CfgEdge::BackEdge))
        .map(|(_, to, _)| *to)
        .collect();

    let mut total_iterations = 0;
    let max_iterations = 500 * cfg.blocks.len();

    while let Some(block_id) = worklist.pop_front() {
        in_worklist.remove(&block_id);
        total_iterations += 1;
        if total_iterations > max_iterations {
            break;
        }

        // Join predecessor exit states with edge refinement
        let Some(mut new_entry) =
            join_predecessor_entry(block_id, cfg, &body, source, macros, &exit_ranges)
        else {
            // No predecessors (unreachable block)
            continue;
        };

        // Apply widening for back-edge targets after threshold
        if back_edge_targets.contains(&block_id) {
            new_entry = maybe_widen(block_id, new_entry, &entry_ranges, &mut block_iterations);
        }

        // Compute exit state
        let block = &cfg.blocks[block_id];
        let new_exit = apply_range_transfer(
            block,
            &new_entry,
            &body,
            source,
            macros,
            summaries,
            &local_types,
        );

        // Check convergence
        let old_exit = exit_ranges.get(&block_id);
        if old_exit.is_none_or(|old| *old != new_exit) {
            entry_ranges.insert(block_id, new_entry);
            exit_ranges.insert(block_id, new_exit);

            for (succ, _) in cfg.successors(block_id) {
                if in_worklist.insert(succ) {
                    worklist.push_back(succ);
                }
            }
        } else {
            entry_ranges.insert(block_id, new_entry);
        }
    }

    // Extract callee return ranges for intra-block replay
    let return_ranges: HashMap<String, ValueRange> = summaries
        .iter()
        .filter_map(|(name, s)| s.return_range.map(|r| (name.clone(), r)))
        .collect();

    RangeAnalysisResult {
        block_entry_ranges: entry_ranges,
        block_exit_ranges: exit_ranges,
        return_ranges,
    }
}

/// An empty range-analysis result (used for skipped/bodyless functions).
fn empty_range_result() -> RangeAnalysisResult {
    RangeAnalysisResult {
        block_entry_ranges: HashMap::new(),
        block_exit_ranges: HashMap::new(),
        return_ranges: HashMap::new(),
    }
}

/// Build the entry-block state from function parameters, narrowing a parameter to
/// a single constant when every caller passes the same integer literal.
fn build_initial_state(
    func_node: &Node,
    source: &str,
    summaries: &HashMap<String, FunctionSummary>,
) -> RangeMap {
    // Build initial state from function parameters
    let mut initial_state = RangeMap::new();
    if let Some(declarator) = func_node.child_by_field_name("declarator") {
        collect_param_ranges(&declarator, source, &mut initial_state);
    }
    // Narrow parameter ranges when ALL callers pass the same integer constant.
    // This suppresses goodG2B-style FPs where data=2 is always safe but VRA
    // would otherwise assign the full type range (e.g. [INT64_MIN, INT64_MAX]).
    if let Some(func_name) = super::function_summary::extract_function_name(func_node, source) {
        if let Some(summary) = summaries.get(&func_name) {
            if !summary.callsite_param_const_int.is_empty() {
                let param_names = super::function_summary::collect_param_names(func_node, source);
                for (&param_idx, &const_val) in &summary.callsite_param_const_int {
                    if let Some(name) = param_names.get(param_idx) {
                        if !name.is_empty() {
                            if let Some(typed_range) = initial_state.get_mut(name) {
                                typed_range.range = ValueRange::new(const_val, const_val);
                            }
                        }
                    }
                }
            }
        }
    }
    initial_state
}

/// Join the exit states of a block's live predecessors (skipping provably-dead
/// constant edges and applying edge refinement). Returns `None` if the block has
/// no live predecessors (unreachable).
fn join_predecessor_entry(
    block_id: BlockId,
    cfg: &FunctionCfg,
    body: &Node,
    source: &str,
    macros: &MacroConstantMap,
    exit_ranges: &HashMap<BlockId, RangeMap>,
) -> Option<RangeMap> {
    let preds = cfg.predecessors(block_id);
    let mut new_entry = RangeMap::new();
    let mut first = true;

    for (pred_id, edge_kind) in &preds {
        // Skip branches that are provably dead due to a constant condition
        if is_dead_constant_edge(*pred_id, edge_kind, cfg, body, source, macros) {
            continue;
        }

        let pred_exit = exit_ranges.get(pred_id).cloned().unwrap_or_default();

        let refined =
            apply_range_edge_refinement(&pred_exit, *pred_id, edge_kind, cfg, body, source, macros);

        if first {
            new_entry = refined;
            first = false;
        } else {
            new_entry = join_range_maps(&new_entry, &refined);
        }
    }

    if first {
        // No predecessors (unreachable block)
        return None;
    }
    Some(new_entry)
}

/// Apply widening to a back-edge target after its iteration threshold: variables
/// whose range grew are pushed out to their type bounds, ensuring termination.
fn maybe_widen(
    block_id: BlockId,
    new_entry: RangeMap,
    entry_ranges: &HashMap<BlockId, RangeMap>,
    block_iterations: &mut HashMap<BlockId, usize>,
) -> RangeMap {
    let count = block_iterations.entry(block_id).or_insert(0);
    *count += 1;
    if *count <= 3 {
        return new_entry;
    }
    // Widen: for each variable, if the range grew, push to type bounds
    let Some(old_entry) = entry_ranges.get(&block_id) else {
        return new_entry;
    };
    let mut widened = new_entry.clone();
    for (var, new_typed) in &new_entry {
        if let Some(old_typed) = old_entry.get(var) {
            widened.insert(var.clone(), widen_typed(old_typed, new_typed));
        }
    }
    widened
}

// ---------------------------------------------------------------------------
// Query API
// ---------------------------------------------------------------------------

/// Get the range of a variable at a specific byte offset within a function.
///
/// Finds the block containing the offset, then simulates forward from the
/// block's entry ranges through statements up to that offset.
pub fn get_var_range_at(
    result: &RangeAnalysisResult,
    cfg: &FunctionCfg,
    body: &Node,
    source: &str,
    macros: &MacroConstantMap,
    var_name: &str,
    byte_offset: usize,
) -> Option<ValueRange> {
    let block = find_block_containing(cfg, byte_offset)?;
    let entry = result.block_entry_ranges.get(&block.id)?;

    // Simulate forward through statements up to (but not past) the offset.
    // Use return ranges stored during the main analysis for intra-block replay.
    let replay_summaries = build_replay_summaries(&result.return_ranges);
    let mut state = entry.clone();
    for &(start, end) in &block.statements {
        if start >= byte_offset {
            break;
        }
        if let Some(stmt_node) = find_node_at_range(body, start, end) {
            let empty_types = HashMap::new();
            process_statement_for_ranges(
                &stmt_node,
                source,
                macros,
                &replay_summaries,
                &mut state,
                &empty_types,
            );
        }
    }

    state.get(var_name).map(|t| t.range)
}

/// Evaluate an expression's range at its location using VRA-computed variable ranges.
pub fn eval_expr_range_at(
    result: &RangeAnalysisResult,
    cfg: &FunctionCfg,
    body: &Node,
    source: &str,
    macros: &MacroConstantMap,
    expr_node: &Node,
) -> Option<ValueRange> {
    let byte_offset = expr_node.start_byte();
    let block = find_block_containing(cfg, byte_offset)?;
    let entry = result.block_entry_ranges.get(&block.id)?;

    // Simulate forward through statements up to (but not past) the expression.
    // Use return ranges stored during the main analysis for intra-block replay.
    let replay_summaries = build_replay_summaries(&result.return_ranges);
    let mut state = entry.clone();
    let empty_types = HashMap::new();
    for &(start, end) in &block.statements {
        if start >= byte_offset {
            break;
        }
        if let Some(stmt_node) = find_node_at_range(body, start, end) {
            process_statement_for_ranges(
                &stmt_node,
                source,
                macros,
                &replay_summaries,
                &mut state,
                &empty_types,
            );
        }
    }

    let var_ranges = extract_var_ranges_from_state(&state);
    const_eval::try_evaluate_range(expr_node, source, macros, &var_ranges)
}

/// Get all variable ranges at `byte_offset` using intra-block forward simulation.
///
/// Unlike reading `block_entry_ranges` directly (which reflects only predecessors),
/// this replays statements from the block entry up to—but not including—the offset.
/// This handles single-block functions and intra-block assignments correctly.
pub fn get_all_var_ranges_at(
    result: &RangeAnalysisResult,
    cfg: &FunctionCfg,
    body: &Node,
    source: &str,
    macros: &MacroConstantMap,
    byte_offset: usize,
) -> Option<VarRangeMap> {
    let block = find_block_containing(cfg, byte_offset)?;
    let entry = result.block_entry_ranges.get(&block.id)?;
    let replay_summaries = build_replay_summaries(&result.return_ranges);
    let mut state = entry.clone();
    let empty_types = HashMap::new();
    for &(start, end) in &block.statements {
        // Stop before the statement containing the offset: its own effects
        // (e.g. `data = data + 1`, or an opaque switch whose case holds the
        // checked expression) must not be applied before evaluation.
        if end > byte_offset {
            break;
        }
        if let Some(stmt_node) = find_node_at_range(body, start, end) {
            process_statement_for_ranges(
                &stmt_node,
                source,
                macros,
                &replay_summaries,
                &mut state,
                &empty_types,
            );
        }
    }
    if state.is_empty() {
        None
    } else {
        Some(extract_var_ranges_from_state(&state))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find the block containing a given byte offset.
fn find_block_containing(cfg: &FunctionCfg, byte_offset: usize) -> Option<&BasicBlock> {
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

/// Extract a simple variable name from an identifier node.
fn extract_simple_var(node: &Node, source: &str) -> Option<String> {
    if node.kind() == "identifier" {
        Some(get_text(node, source))
    } else if node.kind() == "parenthesized_expression" {
        node.child(1)
            .and_then(|inner| extract_simple_var(&inner, source))
    } else {
        None
    }
}

/// Extract a VarRangeMap from the current RangeMap state (for use with try_evaluate_range).
/// Build lightweight FunctionSummary map from stored return ranges for intra-block replay.
fn build_replay_summaries(
    return_ranges: &HashMap<String, ValueRange>,
) -> HashMap<String, FunctionSummary> {
    return_ranges
        .iter()
        .map(|(name, range)| {
            (
                name.clone(),
                FunctionSummary {
                    return_range: Some(*range),
                    ..FunctionSummary::default()
                },
            )
        })
        .collect()
}

/// Resolve a call_expression's return range from function summaries.
///
/// If the node is a `call_expression` and the callee has a `return_range`
/// in its summary, return that range. Otherwise return `None`.
fn resolve_call_return_range(
    node: &Node,
    source: &str,
    summaries: &HashMap<String, FunctionSummary>,
) -> Option<ValueRange> {
    if node.kind() != "call_expression" {
        return None;
    }
    let function_node = node.child_by_field_name("function")?;
    let func_name = function_node
        .utf8_text(source.as_bytes())
        .ok()?
        .trim()
        .to_string();
    let summary = summaries.get(&func_name)?;
    summary.return_range
}

fn extract_var_ranges_from_state(state: &RangeMap) -> VarRangeMap {
    state
        .iter()
        .map(|(name, typed)| (name.clone(), typed.range))
        .collect()
}

/// Get text content of a node.
fn get_text(node: &Node, source: &str) -> String {
    node.utf8_text(source.as_bytes()).unwrap_or("").to_string()
}

/// Get the name from a declarator node (handles pointer_declarator wrapping).
fn get_declarator_name(node: &Node, source: &str) -> String {
    match node.kind() {
        "identifier" => get_text(node, source),
        "pointer_declarator" => {
            // Skip the * and get the inner declarator
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" {
                        return get_text(&child, source);
                    }
                }
            }
            String::new()
        }
        "array_declarator" => {
            if let Some(declarator) = node.child_by_field_name("declarator") {
                get_declarator_name(&declarator, source)
            } else {
                String::new()
            }
        }
        _ => {
            // Try children
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" {
                        return get_text(&child, source);
                    }
                }
            }
            String::new()
        }
    }
}

/// Check if a declarator is a pointer or array type.
fn is_pointer_or_array(node: &Node) -> bool {
    match node.kind() {
        "pointer_declarator" => true,
        "array_declarator" => true,
        _ => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "pointer_declarator" || child.kind() == "array_declarator" {
                        return true;
                    }
                }
            }
            false
        }
    }
}

/// Get the operator text from a binary_expression.
fn get_operator_text(node: &Node, source: &str) -> String {
    // Try field name first
    if let Some(op) = node.child_by_field_name("operator") {
        return get_text(&op, source);
    }
    // Fall back to searching unnamed children
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            let kind = child.kind();
            if matches!(
                kind,
                "<" | "<="
                    | ">"
                    | ">="
                    | "=="
                    | "!="
                    | "&&"
                    | "||"
                    | "+"
                    | "-"
                    | "*"
                    | "/"
                    | "%"
                    | "<<"
                    | ">>"
            ) {
                return kind.to_string();
            }
        }
    }
    String::new()
}

/// Get the assignment operator from an assignment_expression.
fn get_assignment_operator(node: &Node, source: &str) -> String {
    if let Some(op) = node.child_by_field_name("operator") {
        return get_text(&op, source);
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            let kind = child.kind();
            if matches!(kind, "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "<<=" | ">>=") {
                return kind.to_string();
            }
        }
    }
    "=".to_string()
}

/// Extract var name and operator from update_expression (x++, --x, etc.)
fn get_update_info(node: &Node, source: &str) -> (Option<String>, String) {
    let mut var_name = None;
    let mut op = String::new();
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "identifier" {
                var_name = Some(get_text(&child, source));
            } else if child.kind() == "++" || child.kind() == "--" {
                op = child.kind().to_string();
            }
        }
    }
    (var_name, op)
}

/// Collect parameter ranges from a function declarator.
fn collect_param_ranges(declarator: &Node, source: &str, state: &mut RangeMap) {
    // Look for parameter_list in the function_declarator
    let func_decl = if declarator.kind() == "function_declarator" {
        Some(*declarator)
    } else {
        // Might be pointer_declarator wrapping a function_declarator
        find_child_of_kind(declarator, "function_declarator")
    };

    let func_decl = match func_decl {
        Some(fd) => fd,
        None => return,
    };

    if let Some(params) = func_decl.child_by_field_name("parameters") {
        for i in 0..params.child_count() {
            if let Some(param) = params.child(i) {
                if param.kind() == "parameter_declaration" {
                    let var_type = extract_var_type_from_declaration(&param, source);
                    if let Some(decl) = param.child_by_field_name("declarator") {
                        let name = get_declarator_name(&decl, source);
                        if !name.is_empty() && !is_pointer_or_array(&decl) {
                            let range = var_type
                                .as_ref()
                                .map(|t| t.full_range())
                                .unwrap_or(ValueRange::new(i64::MIN, i64::MAX));
                            state.insert(name, TypedRange { range, var_type });
                        }
                    }
                }
            }
        }
    }
}

/// Collect types for uninitialized local variable declarations (e.g., `int data;`).
/// The type information is used as a fallback in assignment processing so that
/// `data = atoi(buf)` uses [INT_MIN, INT_MAX] instead of [i64::MIN, i64::MAX].
fn collect_local_decl_types(body: &Node, source: &str, types: &mut HashMap<String, VarType>) {
    for i in 0..body.named_child_count() {
        if let Some(child) = body.named_child(i) {
            if child.kind() == "declaration" {
                if let Some(var_type) = extract_var_type_from_declaration(&child, source) {
                    if let Some(decl) = child.child_by_field_name("declarator") {
                        if !is_pointer_or_array(&decl) {
                            let name = get_declarator_name(&decl, source);
                            if !name.is_empty() {
                                types.entry(name).or_insert(var_type.clone());
                            }
                        }
                        // Also handle init_declarator
                        if decl.kind() == "init_declarator" {
                            if let Some(inner) = decl.child_by_field_name("declarator") {
                                if !is_pointer_or_array(&inner) {
                                    let name = get_declarator_name(&inner, source);
                                    if !name.is_empty() {
                                        types.entry(name).or_insert(var_type);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if child.kind() == "compound_statement" || child.kind().starts_with("preproc_") {
                collect_local_decl_types(&child, source, types);
            }
        }
    }
}

/// Find a direct child of a specific kind.
fn find_child_of_kind<'a>(node: &Node<'a>, kind: &str) -> Option<Node<'a>> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == kind {
                return Some(child);
            }
            // Recurse one level for wrapper nodes
            if let Some(found) = find_child_of_kind(&child, kind) {
                return Some(found);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::cfg;

    fn parse_and_analyze(code: &str) -> (tree_sitter::Tree, String, Option<RangeAnalysisResult>) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let source = code.to_string();
        let root = tree.root_node();
        let macros = const_eval::collect_macro_constants(&root, &source);

        // Find function_definition
        let func_node = find_first_function(&root);
        let func_node = match func_node {
            Some(n) => n,
            None => return (tree, source, None),
        };

        let function_cfg = cfg::build_function_cfg(&func_node, &source);
        let function_cfg = match function_cfg {
            Some(c) => c,
            None => return (tree, source, None),
        };

        let empty_summaries = HashMap::new();
        let result = analyze_value_ranges(
            &function_cfg,
            &func_node,
            &source,
            &macros,
            &empty_summaries,
        );
        (tree, source, Some(result))
    }

    fn find_first_function<'a>(node: &Node<'a>) -> Option<Node<'a>> {
        if node.kind() == "function_definition" {
            return Some(*node);
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(found) = find_first_function(&child) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// Helper: get range of a variable at a given line (1-based).
    fn get_range_at_line(code: &str, var_name: &str, line: usize) -> Option<ValueRange> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let source = code.to_string();
        let root = tree.root_node();
        let macros = const_eval::collect_macro_constants(&root, &source);

        let func_node = find_first_function(&root)?;
        let function_cfg = cfg::build_function_cfg(&func_node, &source)?;
        let body = func_node.child_by_field_name("body")?;
        let empty_summaries = HashMap::new();
        let result = analyze_value_ranges(
            &function_cfg,
            &func_node,
            &source,
            &macros,
            &empty_summaries,
        );

        // Convert line number to byte offset
        let byte_offset = line_to_byte_offset(&source, line)?;

        get_var_range_at(
            &result,
            &function_cfg,
            &body,
            &source,
            &macros,
            var_name,
            byte_offset,
        )
    }

    fn line_to_byte_offset(source: &str, line: usize) -> Option<usize> {
        let mut current_line = 1;
        for (offset, ch) in source.char_indices() {
            if current_line == line {
                return Some(offset);
            }
            if ch == '\n' {
                current_line += 1;
            }
        }
        if current_line == line {
            Some(source.len())
        } else {
            None
        }
    }

    #[test]
    fn test_simple_assignment() {
        let code = r#"
void f(void) {
    int x = 5;
    int y = x;
}
"#;
        let (_, _, result) = parse_and_analyze(code);
        assert!(result.is_some());
    }

    #[test]
    fn test_if_narrowing() {
        let code = r#"
int f(int x) {
    if (x > 0) {
        return x;
    }
    return 0;
}
"#;
        // After the `if (x > 0)` on the true branch, x should be [1, INT_MAX]
        let (_, _, result) = parse_and_analyze(code);
        assert!(result.is_some());
    }

    #[test]
    fn test_guard_pattern() {
        // if (x == 0) return; — after this, x should be non-zero
        let code = r#"
int f(int x) {
    if (x == 0) return -1;
    return 100 / x;
}
"#;
        let (_, _, result) = parse_and_analyze(code);
        assert!(result.is_some());
    }

    #[test]
    fn test_assignment_propagation() {
        let code = r#"
void f(void) {
    int x = 10;
    int y = x + 5;
    x = 20;
}
"#;
        let range = get_range_at_line(code, "x", 4);
        // After `int x = 10;`, before `int y = x + 5;`, x should be [10, 10]
        assert_eq!(range, Some(ValueRange::exact(10)));
    }

    #[test]
    fn test_loop_convergence() {
        let code = r#"
void f(void) {
    int i = 0;
    while (i < 10) {
        i++;
    }
}
"#;
        let (_, _, result) = parse_and_analyze(code);
        assert!(result.is_some());
        // Should converge without hitting iteration limit
    }

    #[test]
    fn test_compound_and_condition() {
        let code = r#"
int f(int x) {
    if (x >= 0 && x < 100) {
        return x;
    }
    return -1;
}
"#;
        let (_, _, result) = parse_and_analyze(code);
        assert!(result.is_some());
    }

    #[test]
    fn test_unsigned_type_range() {
        let code = r#"
void f(void) {
    unsigned int x = 0;
    x = x + 1;
    int y = x;
}
"#;
        // At line 4 (x = x + 1), x is still [0, 0] — the assignment hasn't run yet
        let range = get_range_at_line(code, "x", 4);
        assert_eq!(range, Some(ValueRange::exact(0)));
        // At line 5 (after x = x + 1 has executed), x should be [1, 1]
        let range = get_range_at_line(code, "x", 5);
        assert_eq!(range, Some(ValueRange::exact(1)));
    }

    #[test]
    fn test_division_guard() {
        // The key pattern: if (divisor == 0) return; — then divisor is safe
        let code = r#"
int safe_div(int a, int b) {
    if (b == 0) return 0;
    return a / b;
}
"#;
        // After the guard, on the false branch of `b == 0`, b should not be [0,0]
        let (_, _, result) = parse_and_analyze(code);
        assert!(result.is_some());
    }

    #[test]
    fn test_eq_zero_guard_narrows_unsigned_fallthrough() {
        // if (b == 0U) return; — on the fall-through path b must be non-zero.
        // For an unsigned int parameter (range [0, UINT32_MAX]), the false branch of
        // `b == 0` should narrow b to [1, UINT32_MAX], not leave it as [0, UINT32_MAX].
        //
        // A dummy statement in the fall-through block before the return ensures that
        // block.byte_range.0 is anchored before the queried line's whitespace.
        // Line numbers: 1=empty, 2=sig, 3=if, 4=dummy, 5=return b, 6=}
        let code = r#"
unsigned int f(unsigned int b) {
    if (b == 0U) return 0U;
    unsigned int keep = b;
    return keep;
}
"#;
        // Line 5 is `    return keep;` — on fall-through b (and keep) should be >= 1
        let range = get_range_at_line(code, "b", 5);
        let r = range.expect("should have range for b at line 5");
        assert!(
            r.min >= 1,
            "b should be >= 1 after == 0 guard, got min={}",
            r.min
        );
    }

    #[test]
    fn test_or_condition_fallthrough_narrows_both_bounds() {
        // if (b == 0U || b >= BITS) return; — rotright pattern.
        // Fall-through: b != 0 AND b < BITS, so b in [1, 31].
        //
        // A dummy statement in the fall-through block before the return ensures
        // block.byte_range.0 is anchored before the queried line's whitespace.
        // Lines: 1=empty, 2=#define, 3=sig, 4=if {, 5=return a, 6=}, 7=dummy, 8=return b, 9=}
        let code = r#"
#define BITS 32U
unsigned int rotright(unsigned int a, unsigned int b) {
    if (b == 0U || b >= BITS) {
        return a;
    }
    unsigned int keep = b;
    return keep;
}
"#;
        // Line 8 is `    return keep;` — after the || guard, b must be in [1, 31]
        let range = get_range_at_line(code, "b", 8);
        let r = range.expect("should have range for b at line 8");
        assert!(
            r.min >= 1,
            "b should be >= 1 after == 0 || >= 32 guard, got min={}",
            r.min
        );
        assert!(
            r.max <= 31,
            "b should be <= 31 after == 0 || >= 32 guard, got max={}",
            r.max
        );
    }

    #[test]
    fn test_negation_condition() {
        let code = r#"
int f(int x) {
    if (!x) return 0;
    return 100 / x;
}
"#;
        let (_, _, result) = parse_and_analyze(code);
        assert!(result.is_some());
    }

    // -----------------------------------------------------------------------
    // Inter-procedural return range tests
    // -----------------------------------------------------------------------

    /// Helper: parse code with multiple functions, compute summaries, and get
    /// the range of a variable at a given line in the LAST function.
    fn get_range_at_line_with_summaries(
        code: &str,
        var_name: &str,
        line: usize,
    ) -> Option<ValueRange> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let source = code.to_string();
        let root = tree.root_node();
        let macros = const_eval::collect_macro_constants(&root, &source);
        let summaries = crate::analyze::function_summary::compute_summaries(
            &root,
            &source,
            &macros,
            true,
            &[],
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
        );

        // Find the last function_definition (the caller)
        fn find_functions<'a>(node: &Node<'a>, out: &mut Vec<Node<'a>>) {
            if node.kind() == "function_definition" {
                out.push(*node);
            }
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    find_functions(&child, out);
                }
            }
        }
        let mut funcs = Vec::new();
        find_functions(&root, &mut funcs);
        let func_node = funcs.last().copied()?;
        let function_cfg = cfg::build_function_cfg(&func_node, &source)?;
        let body = func_node.child_by_field_name("body")?;
        let result = analyze_value_ranges(&function_cfg, &func_node, &source, &macros, &summaries);

        let byte_offset = line_to_byte_offset(&source, line)?;
        get_var_range_at(
            &result,
            &function_cfg,
            &body,
            &source,
            &macros,
            var_name,
            byte_offset,
        )
    }

    #[test]
    fn test_call_constant_return() {
        let code = r#"
int get_five(void) { return 5; }
void caller(void) {
    int x = get_five();
    int y = x;
}
"#;
        // After `int x = get_five();`, x should be [5, 5]
        let range = get_range_at_line_with_summaries(code, "x", 5);
        assert_eq!(range, Some(ValueRange::exact(5)));
    }

    #[test]
    fn test_call_multiple_returns() {
        let code = r#"
int get_bounded(int flag) {
    if (flag) return 1;
    return 10;
}
void caller(void) {
    int x = get_bounded(1);
    int y = x;
}
"#;
        // get_bounded returns [1, 10], so x should be [1, 10]
        let range = get_range_at_line_with_summaries(code, "x", 8);
        assert_eq!(range, Some(ValueRange::new(1, 10)));
    }

    #[test]
    fn test_call_assignment_return_range() {
        let code = r#"
int get_nonzero(void) { return 42; }
void caller(void) {
    int x = 0;
    x = get_nonzero();
    int y = x;
}
"#;
        // After `x = get_nonzero();`, x should be [42, 42]
        let range = get_range_at_line_with_summaries(code, "x", 6);
        assert_eq!(range, Some(ValueRange::exact(42)));
    }

    #[test]
    fn test_call_unevaluable_return() {
        let code = r#"
int get_param(int p) { return p; }
void caller(void) {
    int x = get_param(5);
    int y = x;
}
"#;
        // get_param returns its parameter — not a constant, so return_range is None.
        // x should fall back to full int range.
        let range = get_range_at_line_with_summaries(code, "x", 5);
        assert_eq!(range, Some(ValueRange::new(-2147483648, 2147483647)));
    }
}
