//! Null-state forward dataflow analysis using the CFG.
//!
//! Computes the null/non-null state of pointer variables at every point in a
//! function. Used by EXP34-C to detect null pointer dereferences with proper
//! flow sensitivity through branches, loops, and early returns.

use super::cfg::{BasicBlock, BlockId, CfgEdge, FunctionCfg};
use super::dataflow::find_node_at_range;
use crate::analyze::function_summary::FunctionSummary;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet, VecDeque};
use tree_sitter::Node;

// ---------------------------------------------------------------------------
// Null lattice
// ---------------------------------------------------------------------------

/// Null state for a single pointer variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NullState {
    /// No information (bottom of lattice).
    Unknown,
    /// Definitely assigned NULL / 0 / nullptr.
    DefinitelyNull,
    /// May or may not be null (merged paths, malloc return, etc.).
    PossiblyNull,
    /// Known non-null (checked, assigned &var, assigned non-null literal, etc.).
    NotNull,
}

impl NullState {
    /// Lattice join: merge two states from converging paths.
    pub fn join(self, other: NullState) -> NullState {
        use NullState::*;
        if self == other {
            return self;
        }
        match (self, other) {
            (Unknown, x) | (x, Unknown) => x,
            _ => PossiblyNull,
        }
    }

    /// Returns true if dereference at this state is potentially unsafe.
    pub fn is_unsafe(self) -> bool {
        matches!(self, NullState::DefinitelyNull | NullState::PossiblyNull)
    }
}

/// State map: variable name -> NullState.
pub type StateMap = HashMap<String, NullState>;

/// Join two state maps (union of keys, lattice join per key).
fn join_states(a: &StateMap, b: &StateMap) -> StateMap {
    let mut result = a.clone();
    for (var, &state_b) in b {
        let entry = result.entry(var.clone()).or_insert(NullState::Unknown);
        *entry = entry.join(state_b);
    }
    result
}

// ---------------------------------------------------------------------------
// Analysis result
// ---------------------------------------------------------------------------

/// Result of null-state analysis for one function.
pub struct NullAnalysisResult {
    /// Entry state for each block (after joining predecessors + edge refinement).
    pub block_entry_states: HashMap<BlockId, StateMap>,
    /// Exit state for each block (after simulating block statements).
    #[allow(dead_code)]
    pub block_exit_states: HashMap<BlockId, StateMap>,
    /// Set of variables declared as pointer types.
    pub declared_pointers: HashSet<String>,
}

// ---------------------------------------------------------------------------
// Edge refinement (condition parsing)
// ---------------------------------------------------------------------------

/// Information extracted from a condition for edge refinement.
struct ConditionInfo {
    /// Variable being checked.
    var_name: String,
    /// State on the true-branch edge.
    true_state: NullState,
    /// State on the false-branch edge.
    false_state: NullState,
}

/// Parse a condition AST node and collect ALL null-check conditions.
/// For compound `||` conditions like `ptr == NULL || q == NULL`, returns info
/// for every null-checked variable (not just the first one).
fn parse_all_null_conditions(node: &Node, source: &str) -> Vec<ConditionInfo> {
    match node.kind() {
        "parenthesized_expression" => {
            // Unwrap parens: child(0)='(', child(1)=expr, child(2)=')'
            node.child(1)
                .map(|inner| parse_all_null_conditions(&inner, source))
                .unwrap_or_default()
        }
        "binary_expression" => {
            let Some(left) = node.child_by_field_name("left") else {
                return Vec::new();
            };
            let Some(operator) = node.child_by_field_name("operator") else {
                return Vec::new();
            };
            let Some(right) = node.child_by_field_name("right") else {
                return Vec::new();
            };
            let op = get_text(&operator, source);

            match op.as_str() {
                "==" => {
                    // ptr == NULL  => true: DefinitelyNull, false: NotNull
                    // NULL == ptr  => same
                    if let Some(var) = extract_null_check_var(&left, &right, source) {
                        return vec![ConditionInfo {
                            var_name: var,
                            true_state: NullState::DefinitelyNull,
                            false_state: NullState::NotNull,
                        }];
                    }
                    Vec::new()
                }
                "!=" => {
                    // ptr != NULL  => true: NotNull, false: DefinitelyNull
                    if let Some(var) = extract_null_check_var(&left, &right, source) {
                        return vec![ConditionInfo {
                            var_name: var,
                            true_state: NullState::NotNull,
                            false_state: NullState::DefinitelyNull,
                        }];
                    }
                    Vec::new()
                }
                "||" => {
                    // Collect all null checks from both sides.
                    // On the FALSE branch, ALL conditions are false → all vars NotNull.
                    // On the TRUE branch, at least one is true → conservative (don't refine).
                    let mut all = parse_all_null_conditions(&left, source);
                    all.extend(parse_all_null_conditions(&right, source));
                    all
                }
                "&&" => {
                    // Collect all null checks from both sides.
                    // On the TRUE branch, ALL conditions are true → all vars have true_state.
                    let mut all = parse_all_null_conditions(&left, source);
                    all.extend(parse_all_null_conditions(&right, source));
                    all
                }
                _ => Vec::new(),
            }
        }
        "unary_expression" => {
            // !ptr => true: DefinitelyNull, false: NotNull
            let Some(operator) = node.child(0) else {
                return Vec::new();
            };
            if get_text(&operator, source) == "!" {
                let Some(arg) = node.child_by_field_name("argument") else {
                    return Vec::new();
                };
                if arg.kind() == "identifier" {
                    return vec![ConditionInfo {
                        var_name: get_text(&arg, source),
                        true_state: NullState::DefinitelyNull,
                        false_state: NullState::NotNull,
                    }];
                }
            }
            Vec::new()
        }
        "identifier" => {
            // if (ptr) => true: NotNull, false: DefinitelyNull
            vec![ConditionInfo {
                var_name: get_text(node, source),
                true_state: NullState::NotNull,
                false_state: NullState::DefinitelyNull,
            }]
        }
        _ => Vec::new(),
    }
}

/// Given left and right operands of == or !=, extract the variable name
/// if one side is NULL and the other is an identifier.
fn extract_null_check_var(left: &Node, right: &Node, source: &str) -> Option<String> {
    let lt = get_text(left, source);
    let rt = get_text(right, source);
    if is_null_value(&rt) && left.kind() == "identifier" {
        Some(lt)
    } else if is_null_value(&lt) && right.kind() == "identifier" {
        Some(rt)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Transfer function (per-block simulation)
// ---------------------------------------------------------------------------

/// Simulate a single block's statements on the given entry state,
/// returning the exit state.
fn apply_transfer(
    block: &BasicBlock,
    entry: &StateMap,
    body_node: &Node,
    source: &str,
    declared_pointers: &mut HashSet<String>,
    summaries: &HashMap<String, FunctionSummary>,
) -> StateMap {
    let mut state = entry.clone();
    for &(start, end) in &block.statements {
        if let Some(stmt_node) = find_node_at_range(body_node, start, end) {
            process_statement_for_null_state(
                &stmt_node,
                source,
                &mut state,
                declared_pointers,
                summaries,
            );
        }
    }
    state
}

/// Process a single statement/expression, updating null state.
fn process_statement_for_null_state(
    node: &Node,
    source: &str,
    state: &mut StateMap,
    declared_pointers: &mut HashSet<String>,
    summaries: &HashMap<String, FunctionSummary>,
) {
    // Cross-file output params (task 195/319 follow-on to the EXP33-C fix):
    // any call anywhere in this statement -- bare statement, assignment RHS,
    // or nested inside an if/while condition -- that FunctionSummary::modifies_params
    // says writes through a pointer param marks that param's address-of/bare-array
    // argument NotNull. Applied unconditionally up front (additive, not a dispatch
    // branch) so it doesn't depend on the statement's top-level shape the way
    // process_expression_null's assignment-only dispatch does.
    for call in query::find_descendants_of_kind(*node, "call_expression") {
        apply_cross_file_output_params_null(&call, source, state, summaries);
    }

    match node.kind() {
        "declaration" => {
            process_declaration_null(node, source, state, declared_pointers, summaries);
        }
        "expression_statement" => {
            // Handle assert(var) before other expression processing
            process_assert_for_null_state(node, source, state);
            if let Some(expr) = node.child(0) {
                process_expression_null(&expr, source, state, declared_pointers, summaries);
            }
        }
        "assignment_expression" => {
            process_expression_null(node, source, state, declared_pointers, summaries);
        }
        // Switch statements are opaque in the CFG — walk the body to find
        // declarations and assignments inside case/default blocks.
        "switch_statement" => {
            if let Some(body) = node.child_by_field_name("body") {
                walk_switch_body_for_null_state(&body, source, state, declared_pointers, summaries);
            }
        }
        // Condition expressions (parenthesized_expression at top level of if/while)
        // are added as statements in the condition block. We don't mutate null state
        // from conditions — that's handled by edge refinement.
        _ => {
            // Recognize assert(var) / assert(var != NULL) as making var NotNull
            process_assert_for_null_state(node, source, state);
            // Recurse into compound expressions to find nested assignments
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "assignment_expression" {
                        process_expression_null(
                            &child,
                            source,
                            state,
                            declared_pointers,
                            summaries,
                        );
                    }
                }
            }
        }
    }
}

/// Recursively walk the body of a switch_statement (compound_statement containing
/// case_statement / default nodes) and process all declarations and assignments
/// for null-state tracking.  The switch is opaque in the CFG, so we process
/// all reachable statements sequentially as an approximation.
fn walk_switch_body_for_null_state(
    node: &Node,
    source: &str,
    state: &mut StateMap,
    declared_pointers: &mut HashSet<String>,
    summaries: &HashMap<String, FunctionSummary>,
) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "case_statement" | "compound_statement" => {
                    // Recurse into case/default bodies and compound blocks
                    walk_switch_body_for_null_state(
                        &child,
                        source,
                        state,
                        declared_pointers,
                        summaries,
                    );
                }
                "declaration" | "expression_statement" | "assignment_expression" => {
                    process_statement_for_null_state(
                        &child,
                        source,
                        state,
                        declared_pointers,
                        summaries,
                    );
                }
                _ => {}
            }
        }
    }
}

fn process_declaration_null(
    node: &Node,
    source: &str,
    state: &mut StateMap,
    declared_pointers: &mut HashSet<String>,
    summaries: &HashMap<String, FunctionSummary>,
) {
    for i in 0..node.child_count() {
        let Some(child) = node.child(i) else { continue };
        match child.kind() {
            "init_declarator" => {
                process_init_declarator_null(&child, source, state, declared_pointers, summaries)
            }
            "pointer_declarator" | "identifier" => {
                // Bare uninitialized pointer: "int *ptr;"
                let var_name = get_identifier_from_declarator(&child, source);
                if !var_name.is_empty()
                    && is_pointer_or_array_declarator(&child)
                    && !contains_array(&child)
                {
                    declared_pointers.insert(var_name.clone());
                    state.insert(var_name, NullState::PossiblyNull);
                }
            }
            _ => {}
        }
    }
}

/// `init_declarator` case of [`process_declaration_null`]: resolve the
/// pointer's initial null state, or mark it `PossiblyNull` when declared
/// without an initializer.
fn process_init_declarator_null(
    child: &Node,
    source: &str,
    state: &mut StateMap,
    declared_pointers: &mut HashSet<String>,
    summaries: &HashMap<String, FunctionSummary>,
) {
    let Some(declarator) = child.child_by_field_name("declarator") else {
        return;
    };
    let var_name = get_identifier_from_declarator(&declarator, source);
    if var_name.is_empty() {
        return;
    }
    let is_ptr = is_pointer_or_array_declarator(&declarator) && !contains_array(&declarator);
    if is_ptr {
        declared_pointers.insert(var_name.clone());
    }
    if !is_ptr {
        return;
    }

    match child.child_by_field_name("value") {
        Some(value) => resolve_pointer_init_state(var_name, &value, source, state, summaries),
        None => {
            // Uninitialized pointer
            state.insert(var_name, NullState::PossiblyNull);
        }
    }
}

/// Classify the null state of a pointer's initializer expression, applying
/// same-variable/field/subscript/dereference/cast propagation rules before
/// falling back to the literal classification.
fn resolve_pointer_init_state(
    var_name: String,
    value: &Node,
    source: &str,
    state: &mut StateMap,
    summaries: &HashMap<String, FunctionSummary>,
) {
    let rval = classify_rvalue_null(value, source, summaries);
    if rval == NullState::NotNull {
        if let Some(propagated) = try_propagate_notnull_source_state(value, source, state) {
            state.insert(var_name, propagated);
            return;
        }
    }
    // Propagate pointee state through cast: dataPtr = (T*)voidPtr
    // Variant 64: void pointer cast preserves pointee null state
    if value.kind() == "cast_expression" {
        propagate_cast_pointee_state(&var_name, value, source, state);
    }
    state.insert(var_name, rval);
}

/// When a pointer initializer provably resolves to `NotNull` on its own
/// terms (e.g. `malloc(...)`), check whether it's actually a propagation
/// from another tracked value — a same-named variable (`current = head`), a
/// struct field (`ptr = other->next`), an array element (`data = arr[idx]`,
/// variant 66), or a dereference (`data = *dataPtr`, variant 63/64) — whose
/// *tracked* state should be inherited instead of the literal `NotNull`.
fn try_propagate_notnull_source_state(
    value: &Node,
    source: &str,
    state: &StateMap,
) -> Option<NullState> {
    // Propagate from another variable: Node *current = head;
    if value.kind() == "identifier" {
        let src_name = get_text(value, source);
        if let Some(&src_state) = state.get(&src_name) {
            return Some(src_state);
        }
    }
    // Propagate from field access: ptr = other->next
    if value.kind() == "field_expression" {
        if let Some(arg) = value.child_by_field_name("argument") {
            let base = get_text(&arg, source);
            // Check dotted key first (struct field null propagation)
            if let Some(field_node) = value.child_by_field_name("field") {
                let field_name = get_text(&field_node, source);
                let dotted = format!("{}.{}", base, field_name);
                if let Some(&field_state) = state.get(&dotted) {
                    return Some(field_state);
                }
            }
            if let Some(&base_state) = state.get(&base) {
                if base_state.is_unsafe() {
                    return Some(NullState::PossiblyNull);
                }
            }
        }
    }
    // Propagate from array subscript: data = arr[idx]
    // Variant 66: array element null propagation (uses "arr.idx" dotted key)
    if value.kind() == "subscript_expression" {
        if let (Some(arg), Some(idx)) = (
            value.child_by_field_name("argument"),
            value.child_by_field_name("index"),
        ) {
            let base = get_text(&arg, source);
            let index = get_text(&idx, source);
            let dotted = format!("{}.{}", base, index);
            if let Some(&elem_state) = state.get(&dotted) {
                return Some(elem_state);
            }
        }
    }
    // Propagate from pointer dereference: data = *dataPtr
    // or data = (*dataPtr) (parenthesized form in variant 64)
    // Variant 63/64: pointer-to-pointer null propagation
    extract_deref_pointee_state(value, source, state)
}

/// `dataPtr = (T*)voidPtr` case: void-pointer casts preserve the pointee's
/// null state, tracked under the `*var_name` dereference key (variant 64).
fn propagate_cast_pointee_state(var_name: &str, value: &Node, source: &str, state: &mut StateMap) {
    let Some(inner) = value.child_by_field_name("value") else {
        return;
    };
    let inner = unwrap_parens(&inner);
    if inner.kind() != "identifier" {
        return;
    }
    let inner_name = get_text(&inner, source);
    let src_key = format!("*{}", inner_name);
    if let Some(&s) = state.get(&src_key) {
        let dst_key = format!("*{}", var_name);
        state.insert(dst_key, s);
    }
}

/// Mark `&var`/bare-array output args of `call` as NotNull, using cross-file
/// `FunctionSummary::modifies_params` (task 195/319 follow-on to the EXP33-C
/// fix -- see `Exp33C::build_cross_file_output_params` / `init_state.rs`'s
/// `try_process_cross_file_output_params` for the reference implementation
/// and its "must be additive, not a short-circuit" lesson, which does not
/// apply here since this helper only ever *adds* a NotNull marking and never
/// replaces or skips any other transfer logic).
fn apply_cross_file_output_params_null(
    call: &Node,
    source: &str,
    state: &mut StateMap,
    summaries: &HashMap<String, FunctionSummary>,
) {
    let Some(func) = call.child_by_field_name("function") else {
        return;
    };
    if func.kind() != "identifier" {
        return;
    }
    let func_name = get_text(&func, source);
    let Some(summary) = summaries.get(&func_name) else {
        return;
    };
    if summary.modifies_params.is_empty() {
        return;
    }
    let Some(args) = call.child_by_field_name("arguments") else {
        return;
    };
    let mut arg_idx: usize = 0;
    for i in 0..args.child_count() {
        let Some(arg) = args.child(i) else { continue };
        if matches!(arg.kind(), "," | "(" | ")") {
            continue;
        }
        if summary.modifies_params.contains(&arg_idx) {
            let var_name = extract_output_arg_var(&arg, source);
            if !var_name.is_empty() && state.contains_key(&var_name) {
                state.insert(var_name, NullState::NotNull);
            }
        }
        arg_idx += 1;
    }
}

/// Extract the target variable name from an output-position call argument:
/// `&var` (address-of) or a bare identifier (array-decay / already-a-pointer).
fn extract_output_arg_var(arg: &Node, source: &str) -> String {
    if arg.kind() == "pointer_expression" {
        let text = get_text(arg, source);
        if text.starts_with('&') {
            if let Some(inner) = arg.child_by_field_name("argument") {
                if inner.kind() == "identifier" {
                    return get_text(&inner, source);
                }
            }
        }
    } else if arg.kind() == "identifier" {
        return get_text(arg, source);
    }
    String::new()
}

fn process_expression_null(
    node: &Node,
    source: &str,
    state: &mut StateMap,
    declared_pointers: &HashSet<String>,
    summaries: &HashMap<String, FunctionSummary>,
) {
    if node.kind() != "assignment_expression" {
        return;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };

    let left_name = get_text(&left, source);
    let left_is_ptr = left.kind() != "identifier" || declared_pointers.contains(&left_name);
    if !left_is_ptr {
        return;
    }

    resolve_assignment_null_state(left_name, &right, source, state, summaries);
}

/// Classify the null state of an assignment's RHS, applying the same
/// variable/field/subscript/dereference/cast propagation rules as
/// [`resolve_pointer_init_state`] before falling back to the literal
/// classification.
fn resolve_assignment_null_state(
    left_name: String,
    right: &Node,
    source: &str,
    state: &mut StateMap,
    summaries: &HashMap<String, FunctionSummary>,
) {
    let new_state = classify_rvalue_null(right, source, summaries);
    if new_state == NullState::NotNull {
        if let Some(propagated) = try_propagate_notnull_source_state(right, source, state) {
            state.insert(left_name, propagated);
            return;
        }
    }
    // Propagate pointee state through cast: dataPtr = (T*)voidPtr (variant 64)
    if right.kind() == "cast_expression" {
        propagate_cast_pointee_state(&left_name, right, source, state);
    }
    // Non-nullable function call clears null taint
    if right.kind() == "call_expression" && new_state == NullState::NotNull {
        state.insert(left_name, NullState::NotNull);
        return;
    }
    state.insert(left_name, new_state);
}

/// Recognize an `assert(...)` precondition and mark every pointer the asserted
/// condition proves non-null. Because `assert` evaluates its condition (and the
/// program continues only if it holds), this covers `assert(p)` (truthiness),
/// `assert(p != NULL)`, `assert(p && p->x)` (both `&&` operands hold), and
/// `assert(p->n <= p->m)` (operands are dereferenced, so the base is non-null).
///
/// Conservative: `||`, `!`, and `== NULL` do not establish non-null and are not
/// propagated (SQLite uses these idioms pervasively, so this is the dominant
/// EXP34-C false-positive source on real-world C).
fn process_assert_for_null_state(node: &Node, source: &str, state: &mut StateMap) {
    // Look for expression_statement -> call_expression -> assert
    let call_node = if node.kind() == "expression_statement" {
        node.child(0)
    } else if node.kind() == "call_expression" {
        Some(*node)
    } else {
        None
    };

    let Some(call) = call_node else { return };
    if call.kind() != "call_expression" {
        return;
    }
    let Some(function) = call.child_by_field_name("function") else {
        return;
    };
    if get_text(&function, source) != "assert" {
        return;
    }
    let Some(args) = call.child_by_field_name("arguments") else {
        return;
    };

    // assert() takes a single condition argument.
    for i in 0..args.child_count() {
        if let Some(arg) = args.child(i) {
            if arg.kind() == "(" || arg.kind() == ")" || arg.kind() == "," {
                continue;
            }
            collect_assert_nonnull(&arg, source, true, state);
            return;
        }
    }
}

/// Collect pointers proven non-null by an asserted condition.
///
/// `bool_pos` is true when `node` sits in a boolean/truthiness position
/// (the whole condition, or an operand of `&&`); a bare identifier there is a
/// non-null test. In value position (operands of a comparison such as `<=`) a
/// bare identifier proves nothing, but a dereference of it still does.
fn collect_assert_nonnull(node: &Node, source: &str, bool_pos: bool, state: &mut StateMap) {
    match node.kind() {
        "parenthesized_expression" => {
            if let Some(inner) = node.child(1) {
                collect_assert_nonnull(&inner, source, bool_pos, state);
            }
        }
        "identifier" if bool_pos => {
            state.insert(get_text(node, source), NullState::NotNull);
        }
        // Any dereference proves its base pointer is non-null.
        "field_expression" => {
            if let Some(arg) = node.child_by_field_name("argument") {
                mark_deref_base_nonnull(&arg, source, state);
            }
        }
        "subscript_expression" => {
            if let Some(arg) = node.child(0) {
                mark_deref_base_nonnull(&arg, source, state);
            }
        }
        "pointer_expression" => {
            let is_deref = node
                .child_by_field_name("operator")
                .map(|o| get_text(&o, source) == "*")
                .unwrap_or(false);
            if is_deref {
                if let Some(arg) = node.child_by_field_name("argument") {
                    mark_deref_base_nonnull(&arg, source, state);
                }
            }
        }
        "binary_expression" => {
            let op = node
                .child_by_field_name("operator")
                .map(|o| get_text(&o, source))
                .unwrap_or_default();
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            match op.as_str() {
                "&&" => {
                    if let Some(l) = left {
                        collect_assert_nonnull(&l, source, true, state);
                    }
                    if let Some(r) = right {
                        collect_assert_nonnull(&r, source, true, state);
                    }
                }
                "!=" => {
                    if let (Some(l), Some(r)) = (left, right) {
                        let lt = get_text(&l, source);
                        let rt = get_text(&r, source);
                        if is_null_value(rt.trim()) && l.kind() == "identifier" {
                            state.insert(lt, NullState::NotNull);
                        } else if is_null_value(lt.trim()) && r.kind() == "identifier" {
                            state.insert(rt, NullState::NotNull);
                        } else {
                            collect_assert_nonnull(&l, source, false, state);
                            collect_assert_nonnull(&r, source, false, state);
                        }
                    }
                }
                // `||` only guarantees the left operand evaluates; `!` negates.
                "||" => {
                    if let Some(l) = left {
                        collect_assert_nonnull(&l, source, false, state);
                    }
                }
                // Comparisons/arithmetic (`<=`, `==`, `+`, ...): both operands are
                // evaluated in value position, so derefs within them prove non-null.
                _ => {
                    if let Some(l) = left {
                        collect_assert_nonnull(&l, source, false, state);
                    }
                    if let Some(r) = right {
                        collect_assert_nonnull(&r, source, false, state);
                    }
                }
            }
        }
        _ => {}
    }
}

/// Mark the base identifier of a dereferenced expression as NotNull.
fn mark_deref_base_nonnull(node: &Node, source: &str, state: &mut StateMap) {
    if node.kind() == "identifier" {
        state.insert(get_text(node, source), NullState::NotNull);
    } else {
        // Nested deref (e.g. p->a->b): recurse so the outermost base is marked too.
        collect_assert_nonnull(node, source, false, state);
    }
}

/// Unwrap parenthesized_expression nodes to get the inner expression.
fn unwrap_parens<'a>(node: &'a Node<'a>) -> Node<'a> {
    let mut n = *node;
    while n.kind() == "parenthesized_expression" {
        if let Some(inner) = n.child(1) {
            n = inner;
        } else {
            break;
        }
    }
    n
}

/// Extract pointee null state from a dereference expression (*ptr or (*ptr)).
/// Returns Some(state) if the dereference target has a "*name" key in state.
fn extract_deref_pointee_state(node: &Node, source: &str, state: &StateMap) -> Option<NullState> {
    let inner = unwrap_parens(node);
    if inner.kind() == "pointer_expression" {
        if let Some(op) = inner.child_by_field_name("operator") {
            if get_text(&op, source) == "*" {
                if let Some(arg) = inner.child_by_field_name("argument") {
                    let arg_name = get_text(&arg, source);
                    let deref_key = format!("*{}", arg_name);
                    if let Some(&deref_state) = state.get(&deref_key) {
                        return Some(deref_state);
                    }
                }
            }
        }
    }
    None
}

/// Classify the null state resulting from an rvalue expression.
fn classify_rvalue_null(
    node: &Node,
    source: &str,
    summaries: &HashMap<String, FunctionSummary>,
) -> NullState {
    let text = get_text(node, source);
    let trimmed = text.trim();

    // NULL/0/nullptr
    if is_null_value(trimmed) {
        return NullState::DefinitelyNull;
    }

    // Cast to NULL: (type*)NULL
    if node.kind() == "cast_expression" {
        if let Some(value) = node.child_by_field_name("value") {
            let vt = get_text(&value, source);
            if is_null_value(vt.trim()) {
                return NullState::DefinitelyNull;
            }
        }
    }

    // Nullable function call
    if node.kind() == "call_expression" {
        if let Some(function) = node.child_by_field_name("function") {
            let func_name = get_text(&function, source);
            if is_nullable_function(&func_name, summaries) {
                return NullState::PossiblyNull;
            }
        }
    }

    // Cast wrapping a nullable call
    if node.kind() == "cast_expression" {
        if let Some(value) = node.child_by_field_name("value") {
            if value.kind() == "call_expression" {
                if let Some(function) = value.child_by_field_name("function") {
                    let func_name = get_text(&function, source);
                    if is_nullable_function(&func_name, summaries) {
                        return NullState::PossiblyNull;
                    }
                }
            }
        }
    }

    // Address-of is always non-null
    if node.kind() == "pointer_expression" {
        if let Some(op) = node.child_by_field_name("operator") {
            if get_text(&op, source) == "&" {
                return NullState::NotNull;
            }
        }
    }

    // String literal is always non-null
    if node.kind() == "string_literal" {
        return NullState::NotNull;
    }

    NullState::NotNull
}

// ---------------------------------------------------------------------------
// File-scope global null-state pre-pass
// ---------------------------------------------------------------------------

/// Collect null states for file-scope (static or global) pointer variables.
///
/// Scans all file-scope pointer variable declarations, then walks all function
/// bodies to find assignments to those variables. Returns a map from variable
/// name to its joined null state across all assignment sites.
///
/// Used by EXP34-C to detect patterns like Juliet variant 45:
/// ```c
/// static char *globalData;
/// void bad() { globalData = NULL; badSink(); }
/// void badSink() { char *data = globalData; data[0]; }
/// ```
pub fn collect_file_scope_null_states(
    root: &Node,
    source: &str,
    summaries: &HashMap<String, FunctionSummary>,
) -> StateMap {
    let mut global_vars: HashSet<String> = HashSet::new();
    let mut result: StateMap = StateMap::new();

    // Pass 1: Identify file-scope pointer variable declarations.
    // Walk top-level nodes (and preproc blocks) for declarations.
    collect_file_scope_pointer_decls(root, source, &mut global_vars, &mut result, summaries);

    if global_vars.is_empty() {
        return result;
    }

    // Pass 2: Walk all function bodies for assignments to these globals.
    collect_global_assignments(root, source, &global_vars, &mut result, summaries);

    result
}

/// Identify file-scope pointer declarations and their initializer states.
fn collect_file_scope_pointer_decls(
    node: &Node,
    source: &str,
    global_vars: &mut HashSet<String>,
    result: &mut StateMap,
    summaries: &HashMap<String, FunctionSummary>,
) {
    for i in 0..node.child_count() {
        let child = match node.child(i) {
            Some(c) => c,
            None => continue,
        };

        match child.kind() {
            "declaration" => {
                // Check if any declarator is a pointer type
                for j in 0..child.child_count() {
                    if let Some(declarator) = child.child(j) {
                        if declarator.kind() == "init_declarator" {
                            if let Some(decl) = declarator.child_by_field_name("declarator") {
                                if is_pointer_or_array_declarator(&decl) && !contains_array(&decl) {
                                    let name = get_identifier_from_declarator(&decl, source);
                                    if !name.is_empty() {
                                        global_vars.insert(name.clone());

                                        // Classify the initializer if present
                                        if let Some(value) = declarator.child_by_field_name("value")
                                        {
                                            let state =
                                                classify_rvalue_null(&value, source, summaries);
                                            result.insert(name, state);
                                        }
                                        // No initializer: C default for file-scope is zero/NULL
                                        // but we'll be conservative and leave as Unknown to
                                        // let assignments determine the state
                                    }
                                }
                            }
                        } else if is_pointer_or_array_declarator(&declarator)
                            && !contains_array(&declarator)
                        {
                            // Direct declarator without init (e.g., `static char *p;`)
                            let name = get_identifier_from_declarator(&declarator, source);
                            if !name.is_empty()
                                && declarator.kind() != "storage_class_specifier"
                                && declarator.kind() != "type_qualifier"
                                && declarator.kind() != "primitive_type"
                                && declarator.kind() != "type_identifier"
                            {
                                global_vars.insert(name);
                                // File-scope without initializer: technically zero-initialized
                                // but leave as Unknown to let assignments drive the state
                            }
                        }
                    }
                }
            }
            // Recurse into preprocessor blocks to find declarations
            k if k.starts_with("preproc_") => {
                collect_file_scope_pointer_decls(&child, source, global_vars, result, summaries);
            }
            _ => {}
        }
    }
}

/// Walk all function bodies looking for assignments to file-scope globals.
fn collect_global_assignments(
    node: &Node,
    source: &str,
    global_vars: &HashSet<String>,
    result: &mut StateMap,
    summaries: &HashMap<String, FunctionSummary>,
) {
    for i in 0..node.child_count() {
        let child = match node.child(i) {
            Some(c) => c,
            None => continue,
        };

        match child.kind() {
            "function_definition" => {
                if let Some(body) = child.child_by_field_name("body") {
                    scan_body_for_global_assignments(&body, source, global_vars, result, summaries);
                }
            }
            k if k.starts_with("preproc_") => {
                collect_global_assignments(&child, source, global_vars, result, summaries);
            }
            _ => {}
        }
    }
}

/// Recursively scan a function body for assignments to global variables.
fn scan_body_for_global_assignments(
    node: &Node,
    source: &str,
    global_vars: &HashSet<String>,
    result: &mut StateMap,
    summaries: &HashMap<String, FunctionSummary>,
) {
    if node.kind() == "assignment_expression" {
        if let Some(left) = node.child_by_field_name("left") {
            let var_name = get_text(&left, source);
            if global_vars.contains(&var_name) {
                if let Some(right) = node.child_by_field_name("right") {
                    let rhs_text = get_text(&right, source);
                    // If RHS is itself a variable, check if it's a known global
                    // or classify the rvalue directly
                    let new_state =
                        if right.kind() == "identifier" && global_vars.contains(&rhs_text) {
                            result.get(&rhs_text).copied().unwrap_or(NullState::Unknown)
                        } else if right.kind() == "identifier" {
                            // RHS is a local variable — we can't know its value
                            // from the pre-pass. Check if it's a null literal.
                            if is_null_value(&rhs_text) {
                                NullState::DefinitelyNull
                            } else {
                                // Could be anything — look at what we can infer.
                                // In Juliet variant 45, the pattern is:
                                //   data = NULL; globalVar = data;
                                // We need to check if this local was just assigned NULL.
                                // Since we can't track locals in the pre-pass, check
                                // the preceding statement for a null assignment to this var.
                                check_preceding_null_assign(node, &rhs_text, source)
                            }
                        } else {
                            classify_rvalue_null(&right, source, summaries)
                        };

                    // Join with existing state
                    let existing = result.get(&var_name).copied().unwrap_or(NullState::Unknown);
                    result.insert(var_name, existing.join(new_state));
                }
            }
        }
    }

    // Recurse into children
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            scan_body_for_global_assignments(&child, source, global_vars, result, summaries);
        }
    }
}

/// Check if the preceding statement in the same compound_statement assigns
/// NULL to the given variable. Handles the common Juliet pattern:
///   data = NULL;
///   globalVar = data;
fn check_preceding_null_assign(assignment_node: &Node, var_name: &str, source: &str) -> NullState {
    // Walk up to find the containing expression_statement, then check the previous sibling
    let expr_stmt = if assignment_node.parent().map(|p| p.kind()) == Some("expression_statement") {
        assignment_node.parent().unwrap()
    } else {
        return NullState::Unknown;
    };

    if let Some(prev) = expr_stmt.prev_sibling() {
        if prev.kind() == "expression_statement" {
            if let Some(expr) = prev.child(0) {
                if expr.kind() == "assignment_expression" {
                    if let Some(left) = expr.child_by_field_name("left") {
                        if get_text(&left, source) == var_name {
                            if let Some(right) = expr.child_by_field_name("right") {
                                let rhs = get_text(&right, source);
                                if is_null_value(rhs.trim()) {
                                    return NullState::DefinitelyNull;
                                }
                                // Non-null assignment (e.g., data = "Good")
                                return classify_rvalue_null(&right, source, &HashMap::new());
                            }
                        }
                    }
                }
            }
        }
        // Check for declaration: `char *data = NULL;` or `char *data;`
        if prev.kind() == "declaration" {
            for i in 0..prev.child_count() {
                if let Some(child) = prev.child(i) {
                    if child.kind() == "init_declarator" {
                        if let Some(decl) = child.child_by_field_name("declarator") {
                            let name = get_identifier_from_declarator(&decl, source);
                            if name == var_name {
                                if let Some(value) = child.child_by_field_name("value") {
                                    let vtext = get_text(&value, source);
                                    if is_null_value(vtext.trim()) {
                                        return NullState::DefinitelyNull;
                                    }
                                    return classify_rvalue_null(&value, source, &HashMap::new());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    NullState::Unknown
}

// ---------------------------------------------------------------------------
// Forward dataflow (worklist algorithm)
// ---------------------------------------------------------------------------

/// Run null-state forward dataflow on a function CFG.
///
/// `func_node` is the `function_definition` AST node (for param extraction).
/// `source` is the full source text.
/// `summaries` are inter-procedural function summaries.
#[allow(dead_code)]
pub fn analyze_null_states(
    cfg: &FunctionCfg,
    func_node: &Node,
    source: &str,
    summaries: &HashMap<String, FunctionSummary>,
) -> NullAnalysisResult {
    analyze_null_states_with_globals(cfg, func_node, source, summaries, &StateMap::new(), None)
}

/// Like `analyze_null_states` but seeds the initial state with file-scope
/// global variable null states collected by `collect_file_scope_null_states`.
///
/// If `func_name` is provided, uses call-site-derived parameter null states
/// from `summaries[func_name].callsite_param_null_states` to seed parameters
/// instead of blanket PossiblyNull.
pub fn analyze_null_states_with_globals(
    cfg: &FunctionCfg,
    func_node: &Node,
    source: &str,
    summaries: &HashMap<String, FunctionSummary>,
    global_states: &StateMap,
    func_name: Option<&str>,
) -> NullAnalysisResult {
    let body = match func_node.child_by_field_name("body") {
        Some(b) => b,
        None => {
            return NullAnalysisResult {
                block_entry_states: HashMap::new(),
                block_exit_states: HashMap::new(),
                declared_pointers: HashSet::new(),
            }
        }
    };

    let (initial_state, mut declared_pointers) =
        seed_initial_null_state(func_node, source, summaries, global_states, func_name);

    let mut entry_states: HashMap<BlockId, StateMap> = HashMap::new();
    let mut exit_states: HashMap<BlockId, StateMap> = HashMap::new();

    // Initialize all blocks
    for block in &cfg.blocks {
        entry_states.insert(block.id, StateMap::new());
        exit_states.insert(block.id, StateMap::new());
    }

    // Entry block gets initial state
    entry_states.insert(cfg.entry, initial_state.clone());
    let entry_exit = apply_transfer(
        &cfg.blocks[cfg.entry],
        &initial_state,
        &body,
        source,
        &mut declared_pointers,
        summaries,
    );
    exit_states.insert(cfg.entry, entry_exit);

    run_null_state_worklist(
        cfg,
        &body,
        source,
        summaries,
        &mut declared_pointers,
        &mut entry_states,
        &mut exit_states,
    );

    NullAnalysisResult {
        block_entry_states: entry_states,
        block_exit_states: exit_states,
        declared_pointers,
    }
}

/// Build the entry-block null-state seed: global variable states, then
/// (if the function's declarator is available) call-site-derived parameter
/// states, struct-field states (variant 67), and pointer-to-pointer pointee
/// states (variant 63).
fn seed_initial_null_state(
    func_node: &Node,
    source: &str,
    summaries: &HashMap<String, FunctionSummary>,
    global_states: &StateMap,
    func_name: Option<&str>,
) -> (StateMap, HashSet<String>) {
    let mut declared_pointers = HashSet::new();
    let mut initial_state = StateMap::new();

    // Seed with global variable states
    for (name, &state) in global_states {
        initial_state.insert(name.clone(), state);
        declared_pointers.insert(name.clone());
    }

    // Look up call-site-derived param states if func_name is available
    let func_summary = func_name.and_then(|name| summaries.get(name));
    let callsite_states = func_summary.map(|s| &s.callsite_param_null_states);

    let Some(declarator) = func_node.child_by_field_name("declarator") else {
        return (initial_state, declared_pointers);
    };
    collect_param_pointer_state(
        &declarator,
        source,
        &mut initial_state,
        &mut declared_pointers,
        callsite_states,
    );

    if let Some(summary) = func_summary {
        seed_callsite_field_null_states(func_node, source, summary, &mut initial_state);
        seed_callsite_pointee_null_states(func_node, source, summary, &mut initial_state);
    }

    (initial_state, declared_pointers)
}

/// Seed struct field null states: "paramName.fieldName" → NullState.
/// Enables variant 67 detection (struct field null propagation across functions).
fn seed_callsite_field_null_states(
    func_node: &Node,
    source: &str,
    summary: &FunctionSummary,
    initial_state: &mut StateMap,
) {
    if summary.callsite_param_field_null_states.is_empty() {
        return;
    }
    let param_names = crate::analyze::function_summary::collect_param_names(func_node, source);
    for (param_idx, field_states) in &summary.callsite_param_field_null_states {
        let Some(param_name) = param_names.get(*param_idx) else {
            continue;
        };
        if param_name.is_empty() {
            continue;
        }
        for (field_name, &state) in field_states {
            let key = format!("{}.{}", param_name, field_name);
            initial_state.insert(key, state);
        }
    }
}

/// Seed pointer-to-pointer pointee null states: "*paramName" → NullState.
/// Enables variant 63 detection (pointer-to-pointer null propagation) — when
/// caller passes `&data` where `data=NULL`, sink receives `**param` and
/// `*param` yields the NULL pointer.
fn seed_callsite_pointee_null_states(
    func_node: &Node,
    source: &str,
    summary: &FunctionSummary,
    initial_state: &mut StateMap,
) {
    if summary.callsite_param_pointee_null_states.is_empty() {
        return;
    }
    let param_names = crate::analyze::function_summary::collect_param_names(func_node, source);
    for (param_idx, &state) in &summary.callsite_param_pointee_null_states {
        let Some(param_name) = param_names.get(*param_idx) else {
            continue;
        };
        if param_name.is_empty() {
            continue;
        }
        let key = format!("*{}", param_name);
        initial_state.insert(key, state);
    }
}

/// Run the forward-dataflow worklist fixpoint over the CFG, updating
/// `entry_states`/`exit_states` in place.
#[allow(clippy::too_many_arguments)]
fn run_null_state_worklist(
    cfg: &FunctionCfg,
    body: &Node,
    source: &str,
    summaries: &HashMap<String, FunctionSummary>,
    declared_pointers: &mut HashSet<String>,
    entry_states: &mut HashMap<BlockId, StateMap>,
    exit_states: &mut HashMap<BlockId, StateMap>,
) {
    // Worklist — companion set for O(1) membership test instead of O(N) VecDeque::contains.
    let mut worklist: VecDeque<BlockId> = VecDeque::new();
    let mut in_worklist: HashSet<BlockId> = HashSet::new();
    for (succ, _) in cfg.successors(cfg.entry) {
        worklist.push_back(succ);
        in_worklist.insert(succ);
    }

    let mut iterations = 0;
    const MAX_ITERATIONS: usize = 500;

    while let Some(block_id) = worklist.pop_front() {
        in_worklist.remove(&block_id);
        iterations += 1;
        if iterations > MAX_ITERATIONS * cfg.blocks.len() {
            break;
        }

        // Join predecessor exit states with edge refinement
        let preds = cfg.predecessors(block_id);
        let mut new_entry = StateMap::new();
        let mut first = true;

        for (pred_id, edge_kind) in &preds {
            let pred_exit = exit_states.get(pred_id).cloned().unwrap_or_default();

            // Apply edge refinement from condition
            let refined = apply_edge_refinement(&pred_exit, *pred_id, edge_kind, cfg, body, source);

            if first {
                new_entry = refined;
                first = false;
            } else {
                new_entry = join_states(&new_entry, &refined);
            }
        }

        if first {
            // No predecessors (unreachable block)
            continue;
        }

        // Compute exit state
        let block = &cfg.blocks[block_id];
        let new_exit = apply_transfer(
            block,
            &new_entry,
            body,
            source,
            declared_pointers,
            summaries,
        );

        // Check convergence
        let old_exit = exit_states.get(&block_id);
        if old_exit.is_none_or(|old| *old != new_exit) {
            entry_states.insert(block_id, new_entry);
            exit_states.insert(block_id, new_exit);

            // Add successors to worklist
            for (succ, _) in cfg.successors(block_id) {
                if in_worklist.insert(succ) {
                    worklist.push_back(succ);
                }
            }
        } else {
            entry_states.insert(block_id, new_entry);
        }
    }
}

/// Apply edge refinement: given a predecessor's exit state and the edge type,
/// refine the state based on the predecessor's condition.
fn apply_edge_refinement(
    pred_exit: &StateMap,
    pred_id: BlockId,
    edge_kind: &CfgEdge,
    cfg: &FunctionCfg,
    body: &Node,
    source: &str,
) -> StateMap {
    let mut state = pred_exit.clone();

    // Only refine on TrueBranch/FalseBranch edges
    let is_true = matches!(edge_kind, CfgEdge::TrueBranch);
    let is_false = matches!(edge_kind, CfgEdge::FalseBranch);
    if !is_true && !is_false {
        return state;
    }

    // Get the condition range from the predecessor block
    let pred_block = match cfg.get_block(pred_id) {
        Some(b) => b,
        None => return state,
    };
    let (cond_start, cond_end) = match pred_block.condition_range {
        Some(r) => r,
        None => return state,
    };

    // Find the condition AST node
    let cond_node = match find_node_at_range(body, cond_start, cond_end) {
        Some(n) => n,
        None => return state,
    };

    // Parse condition for null-check info (all vars in compound conditions)
    for info in parse_all_null_conditions(&cond_node, source) {
        let refined_state = if is_true {
            info.true_state
        } else {
            info.false_state
        };
        // Only refine if the variable is tracked
        if state.contains_key(&info.var_name) {
            state.insert(info.var_name, refined_state);
        }
    }

    state
}

// ---------------------------------------------------------------------------
// Dereference query
// ---------------------------------------------------------------------------

/// Check if dereferencing `var_name` at byte offset `deref_byte` is potentially unsafe.
///
/// Finds the block containing `deref_byte`, simulates from block entry up to
/// that point, and returns true if the variable is in an unsafe null state.
pub fn is_null_deref_at(
    result: &NullAnalysisResult,
    cfg: &FunctionCfg,
    body: &Node,
    source: &str,
    var_name: &str,
    deref_byte: usize,
    summaries: &HashMap<String, FunctionSummary>,
) -> bool {
    // Find which block contains this dereference
    let block = match find_block_containing(cfg, deref_byte) {
        Some(b) => b,
        None => return false, // Can't determine — be conservative
    };

    // Get entry state for this block
    let entry = match result.block_entry_states.get(&block.id) {
        Some(s) => s,
        None => return false,
    };

    // Simulate forward from entry through statements up to the dereference
    let mut state = entry.clone();
    let mut declared_pointers = result.declared_pointers.clone();

    for &(start, end) in &block.statements {
        // Stop before processing statements that come after the dereference
        if start >= deref_byte {
            break;
        }
        if let Some(stmt_node) = find_node_at_range(body, start, end) {
            process_statement_for_null_state(
                &stmt_node,
                source,
                &mut state,
                &mut declared_pointers,
                summaries,
            );
        }
    }

    // Check variable's state at dereference point
    match state.get(var_name) {
        Some(ns) => ns.is_unsafe(),
        None => false, // Unknown variable — not tracked as pointer
    }
}

/// Query the null state of a variable at a given byte offset.
///
/// Returns the concrete NullState (not just unsafe/safe). Used by call-site
/// null propagation to distinguish DefinitelyNull from PossiblyNull.
pub fn get_var_state_at(
    result: &NullAnalysisResult,
    cfg: &FunctionCfg,
    body: &Node,
    source: &str,
    var_name: &str,
    byte_offset: usize,
    summaries: &HashMap<String, FunctionSummary>,
) -> NullState {
    let block = match find_block_containing(cfg, byte_offset) {
        Some(b) => b,
        None => return NullState::Unknown,
    };

    let entry = match result.block_entry_states.get(&block.id) {
        Some(s) => s,
        None => return NullState::Unknown,
    };

    let mut state = entry.clone();
    let mut declared_pointers = result.declared_pointers.clone();

    for &(start, end) in &block.statements {
        if start >= byte_offset {
            break;
        }
        if let Some(stmt_node) = find_node_at_range(body, start, end) {
            process_statement_for_null_state(
                &stmt_node,
                source,
                &mut state,
                &mut declared_pointers,
                summaries,
            );
        }
    }

    state.get(var_name).copied().unwrap_or(NullState::Unknown)
}

/// Find the basic block whose byte range contains the given offset.
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

// ---------------------------------------------------------------------------
// Parameter collection
// ---------------------------------------------------------------------------

fn collect_param_pointer_state(
    declarator: &Node,
    source: &str,
    state: &mut StateMap,
    declared_pointers: &mut HashSet<String>,
    callsite_states: Option<&HashMap<usize, NullState>>,
) {
    if declarator.kind() == "function_declarator" {
        if let Some(params) = declarator.child_by_field_name("parameters") {
            let mut param_idx: usize = 0;
            for i in 0..params.child_count() {
                if let Some(param) = params.child(i) {
                    if param.kind() == "parameter_declaration" {
                        let param_text = get_text(&param, source);
                        if let Some(param_decl) = param.child_by_field_name("declarator") {
                            let name = get_identifier_from_declarator(&param_decl, source);
                            if !name.is_empty()
                                && (is_pointer_or_array_declarator(&param_decl)
                                    || param_text.contains('*')
                                    || param_text.starts_with("FILE")
                                    || name.contains("callback"))
                            {
                                declared_pointers.insert(name.clone());
                                // Use call-site-derived state if available,
                                // falling back to PossiblyNull (default)
                                let seed_state = if let Some(cs) = callsite_states {
                                    // Have inter-procedural call-site data.
                                    // If prescan resolved a concrete state, use it.
                                    // If Unknown or missing, treat as NotNull — same
                                    // as no-callsite-data ("callers are responsible").
                                    cs.get(&param_idx)
                                        .copied()
                                        .map(|s| match s {
                                            NullState::Unknown => NullState::NotNull,
                                            other => other,
                                        })
                                        .unwrap_or(NullState::NotNull)
                                } else {
                                    // No call-site data — assume params are non-null
                                    // (callers are responsible for null checks)
                                    NullState::NotNull
                                };
                                state.insert(name, seed_state);
                            }
                        }
                        param_idx += 1;
                    }
                }
            }
        }
    } else {
        for i in 0..declarator.child_count() {
            if let Some(child) = declarator.child(i) {
                collect_param_pointer_state(
                    &child,
                    source,
                    state,
                    declared_pointers,
                    callsite_states,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions (shared with EXP34-C)
// ---------------------------------------------------------------------------

fn get_text(node: &Node, source: &str) -> String {
    source[node.start_byte()..node.end_byte()].to_string()
}

/// Whether trimmed `text` is a literal null spelling (`NULL`, `0`, `nullptr`).
pub fn is_null_value(text: &str) -> bool {
    let t = text.trim();
    t == "NULL" || t == "0" || t == "nullptr"
}

/// Whether `func_name` may return NULL: either its [`FunctionSummary`] says
/// so, or it's one of a fixed list of standard-library/POSIX/sqlite
/// functions known to be nullable.
pub fn is_nullable_function(func_name: &str, summaries: &HashMap<String, FunctionSummary>) -> bool {
    if let Some(summary) = summaries.get(func_name) {
        if summary.can_return_null {
            return true;
        }
    }
    matches!(
        func_name,
        "malloc"
            | "calloc"
            | "realloc"
            // sqlite's own allocator wrappers (ext/misc/vfstrace.c:895-class FN,
            // task 173): sqlite3_malloc/sqlite3_malloc64 return NULL on OOM just
            // like the stdlib functions they wrap, but aren't in FunctionSummary
            // unless the whole sqlite3 source tree is in the -d prescan set.
            | "sqlite3_malloc"
            | "sqlite3_malloc64"
            | "sqlite3_realloc"
            | "sqlite3_realloc64"
            | "strstr"
            | "strchr"
            | "strrchr"
            | "fopen"
            | "fdopen"
            | "freopen"
            | "tmpfile"
            | "popen"
            | "getenv"
            | "setlocale"
            | "strtok"
            | "bsearch"
            | "fgets"
            | "gets"
            | "strdup"
            | "strndup"
            | "strpbrk"
            | "memchr"
            | "localtime"
            | "gmtime"
            | "asctime"
            | "ctime"
            | "create_int"
    )
}

/// Whether `node` is a cast expression whose value is a null literal (e.g. `(void*)0`).
#[allow(dead_code)]
pub fn is_cast_to_null(node: &Node, source: &str) -> bool {
    if node.kind() == "cast_expression" {
        if let Some(value) = node.child_by_field_name("value") {
            let vt = get_text(&value, source);
            return is_null_value(vt.trim());
        }
    }
    false
}

/// Whether `declarator` is, or nests, a pointer or array declarator.
///
/// Not the same predicate as
/// `declarator_utils::is_pointer_declarator` (task 584): that one asks
/// "does a `pointer_declarator` occur anywhere in this tree", so a bare
/// array (`int arr[10];`, no pointer anywhere) is `false`. This one
/// short-circuits `true` at the first `array_declarator` it sees, so a
/// bare array is `true` here. Most call sites in this file pair this with
/// `!contains_array(..)`, which cancels the difference back out to "has a
/// pointer_declarator and is not an array" -- but `EXP34-C` calls this one
/// alone (arrays decay to pointers at a call site, which is the case it
/// wants to treat as "declared pointer"), so the two functions cannot be
/// collapsed into one without changing that behavior.
pub fn is_pointer_or_array_declarator(declarator: &Node) -> bool {
    match declarator.kind() {
        "pointer_declarator" => true,
        "array_declarator" => true,
        _ => {
            for i in 0..declarator.child_count() {
                if let Some(child) = declarator.child(i) {
                    if is_pointer_or_array_declarator(&child) {
                        return true;
                    }
                }
            }
            false
        }
    }
}

fn contains_array(node: &Node) -> bool {
    if node.kind() == "array_declarator" {
        return true;
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if contains_array(&child) {
                return true;
            }
        }
    }
    false
}

fn get_identifier_from_declarator(declarator: &Node, source: &str) -> String {
    match declarator.kind() {
        "identifier" => get_text(declarator, source),
        "pointer_declarator" | "array_declarator" => {
            if let Some(inner) = declarator.child_by_field_name("declarator") {
                get_identifier_from_declarator(&inner, source)
            } else {
                String::new()
            }
        }
        _ => {
            for i in 0..declarator.child_count() {
                if let Some(child) = declarator.child(i) {
                    if child.kind() == "identifier" {
                        return get_text(&child, source);
                    }
                }
            }
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::cfg::build_function_cfg;

    fn analyze(code: &str) -> (FunctionCfg, NullAnalysisResult, tree_sitter::Tree, String) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let root = tree.root_node();
        let func = (0..root.child_count())
            .filter_map(|i| root.child(i))
            .find(|c| c.kind() == "function_definition")
            .unwrap();
        let cfg = build_function_cfg(&func, code).unwrap();
        let summaries = HashMap::new();
        let result = analyze_null_states(&cfg, &func, code, &summaries);
        (cfg, result, tree, code.to_string())
    }

    #[test]
    fn test_null_assigned_then_deref() {
        let code = r#"
void foo() {
    int *p = NULL;
    *p = 42;
}
"#;
        let (cfg, result, tree, source) = analyze(code);
        let root = tree.root_node();
        let func = root.child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();
        // Find dereference byte — "*p = 42"
        let deref_pos = source.find("*p = 42").unwrap();
        let summaries = HashMap::new();
        assert!(is_null_deref_at(
            &result, &cfg, &body, &source, "p", deref_pos, &summaries
        ));
    }

    #[test]
    fn test_cross_file_output_param_marks_not_null() {
        // task 195/319 follow-on: a cross-file function known from
        // FunctionSummary::modifies_params to write through param index 0
        // must clear NullState for the address-of'd variable, including when
        // the call sits inside an if-condition and is not wrapped in an
        // rc = call(); if (rc == ...) pattern.
        let code = r#"
void foo(void) {
    struct thing *out = NULL;
    if (fetch_thing(&out) < 0)
        return;
    use(out->field);
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let root = tree.root_node();
        let func = (0..root.child_count())
            .filter_map(|i| root.child(i))
            .find(|c| c.kind() == "function_definition")
            .unwrap();
        let cfg = build_function_cfg(&func, code).unwrap();
        let body = func.child_by_field_name("body").unwrap();

        let mut summary = FunctionSummary::default();
        summary.modifies_params.insert(0);
        let mut summaries = HashMap::new();
        summaries.insert("fetch_thing".to_string(), summary);

        let result = analyze_null_states(&cfg, &func, code, &summaries);
        let use_pos = code.find("out->field").unwrap();
        assert!(
            !is_null_deref_at(&result, &cfg, &body, code, "out", use_pos, &summaries),
            "out should be NotNull via the cross-file output-param call, even though \
             it sits inside an if-condition rather than an rc = call(); if (rc==...) pattern"
        );
    }

    #[test]
    fn test_null_check_before_deref() {
        let code = r#"
void foo() {
    int *p = NULL;
    if (p != NULL) {
        *p = 42;
    }
}
"#;
        let (cfg, result, tree, source) = analyze(code);
        let root = tree.root_node();
        let func = root.child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let deref_pos = source.find("*p = 42").unwrap();
        let summaries = HashMap::new();
        assert!(!is_null_deref_at(
            &result, &cfg, &body, &source, "p", deref_pos, &summaries
        ));
    }

    #[test]
    fn test_early_return_after_null_check() {
        let code = r#"
int foo(int *p) {
    if (p == NULL) {
        return -1;
    }
    *p = 42;
    return 0;
}
"#;
        let (cfg, result, tree, source) = analyze(code);
        let root = tree.root_node();
        let func = root.child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let deref_pos = source.find("*p = 42").unwrap();
        let summaries = HashMap::new();
        assert!(!is_null_deref_at(
            &result, &cfg, &body, &source, "p", deref_pos, &summaries
        ));
    }

    #[test]
    fn test_deref_inside_null_branch() {
        let code = r#"
void foo(int *p) {
    if (p == NULL) {
        *p = 42;
    }
}
"#;
        let (cfg, result, tree, source) = analyze(code);
        let root = tree.root_node();
        let func = root.child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let deref_pos = source.find("*p = 42").unwrap();
        let summaries = HashMap::new();
        assert!(is_null_deref_at(
            &result, &cfg, &body, &source, "p", deref_pos, &summaries
        ));
    }

    #[test]
    fn test_malloc_with_check() {
        let code = r#"
void foo() {
    int *p = malloc(sizeof(int));
    if (p == NULL) {
        return;
    }
    *p = 42;
}
"#;
        let (cfg, result, tree, source) = analyze(code);
        let root = tree.root_node();
        let func = root.child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let deref_pos = source.find("*p = 42").unwrap();
        let summaries = HashMap::new();
        assert!(!is_null_deref_at(
            &result, &cfg, &body, &source, "p", deref_pos, &summaries
        ));
    }

    #[test]
    fn test_malloc_without_check() {
        let code = r#"
void foo() {
    int *p = malloc(sizeof(int));
    *p = 42;
}
"#;
        let (cfg, result, tree, source) = analyze(code);
        let root = tree.root_node();
        let func = root.child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let deref_pos = source.find("*p = 42").unwrap();
        let summaries = HashMap::new();
        assert!(is_null_deref_at(
            &result, &cfg, &body, &source, "p", deref_pos, &summaries
        ));
    }

    #[test]
    fn test_while_loop_guard() {
        let code = r#"
void foo(int *p) {
    while (p != NULL) {
        *p = 42;
        p = NULL;
    }
}
"#;
        let (cfg, result, tree, source) = analyze(code);
        let root = tree.root_node();
        let func = root.child(0).unwrap();
        let body = func.child_by_field_name("body").unwrap();
        let deref_pos = source.find("*p = 42").unwrap();
        let summaries = HashMap::new();
        assert!(!is_null_deref_at(
            &result, &cfg, &body, &source, "p", deref_pos, &summaries
        ));
    }

    #[test]
    fn test_global_prepass_null_static() {
        // Variant 45 pattern: static global assigned NULL, read in sink function
        let code = r#"
static int *globalData;

void source() {
    int *data;
    data = NULL;
    globalData = data;
}

void sink() {
    int *data = globalData;
    *data = 42;
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let root = tree.root_node();
        let summaries = HashMap::new();

        let globals = collect_file_scope_null_states(&root, code, &summaries);
        assert_eq!(globals.get("globalData"), Some(&NullState::DefinitelyNull));

        // Now analyze sink() with global states
        let sink_func = (0..root.child_count())
            .filter_map(|i| root.child(i))
            .find(|c| {
                c.kind() == "function_definition"
                    && code[c.start_byte()..c.end_byte()].contains("sink")
            })
            .unwrap();
        let cfg = build_function_cfg(&sink_func, code).unwrap();
        let result =
            analyze_null_states_with_globals(&cfg, &sink_func, code, &summaries, &globals, None);
        let body = sink_func.child_by_field_name("body").unwrap();
        let deref_pos = code.find("*data = 42").unwrap();
        assert!(is_null_deref_at(
            &result, &cfg, &body, code, "data", deref_pos, &summaries
        ));
    }

    #[test]
    fn test_global_prepass_nonnull_static() {
        // Good variant: static global assigned non-null, should NOT flag
        let code = r#"
static char *globalData;

void source() {
    char *data;
    data = "Good";
    globalData = data;
}

void sink() {
    char *data = globalData;
    data[0];
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let root = tree.root_node();
        let summaries = HashMap::new();

        let globals = collect_file_scope_null_states(&root, code, &summaries);
        assert_eq!(globals.get("globalData"), Some(&NullState::NotNull));
    }
}
