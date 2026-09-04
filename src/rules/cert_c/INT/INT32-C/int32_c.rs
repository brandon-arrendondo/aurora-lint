use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::FunctionCfg;
use crate::analyze::const_eval::{self, MacroConstantMap, VarRangeMap};
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::macro_expand::FunctionMacro;
use crate::analyze::value_range::RangeAnalysisResult;
use crate::analyze::vra_access;
use crate::manifest::{RuleCategory, Severity};
use crate::rules::cert_c::int_provenance;
use crate::utility::cert_c::ast_utils::{self, get_node_text, get_sanitized_node_text};
use crate::utility::cert_c::float_typing;
use crate::utility::cert_c::overflow_helpers;
use crate::utility::cert_c::std_functions;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// Width, in bits, at which C actually performs integer arithmetic on
/// anything `int`-wide or narrower. The usual arithmetic conversions promote
/// every narrower type to `int` first, so there is no such thing as 8- or
/// 16-bit arithmetic to check against.
const PROMOTED_ARITH_BITS: u32 = 32;

pub struct Int32C {
    project_macros: RefCell<MacroConstantMap>,
    current_macros: RefCell<MacroConstantMap>,
    struct_field_types: RefCell<HashMap<String, HashMap<String, String>>>,
    /// One-level typedef alias map (`word_t` -> `unsigned long`, `paddr_t` ->
    /// `word_t`, ...), populated project-wide by `set_project_context`.
    /// Resolved recursively by `overflow_helpers::typedef_chain_is_unsigned`
    /// in `classify_declared_type` (task 657).
    typedef_types: RefCell<HashMap<String, String>>,
    /// Function-like macro definitions, project-wide (task 676). Lets
    /// `infer_type` recognize a call-like operand (e.g. seL4's `BIT(n)`) as
    /// unsigned via `macro_yields_unsigned_constant` rather than falling
    /// through to "unknown" and flagging a signed-overflow FP on
    /// arithmetic that's actually unsigned.
    function_macros: RefCell<HashMap<String, FunctionMacro>>,
    function_cfgs: RefCell<HashMap<usize, FunctionCfg>>,
    vra_results: RefCell<HashMap<usize, RangeAnalysisResult>>,
    function_summaries: RefCell<HashMap<String, FunctionSummary>>,
    /// Globals known to be written by a tainted function (file → function name
    /// set). Used by the provenance gate to treat a global operand fed from an
    /// untrusted source as risky.
    global_writers: RefCell<HashMap<String, HashSet<String>>>,
    /// Per-function memo of variable names fed from a risky source, keyed by the
    /// containing function's tree-sitter node id. Computed once per function by a
    /// single body walk (avoids re-walking the body for every arithmetic
    /// operand). Cleared at the start of each `check()` (node ids are unique only
    /// within one parse tree).
    risky_vars_cache: RefCell<HashMap<usize, HashSet<String>>>,
    /// Per-function memo of `get_sanitized_node_text`, keyed by the containing
    /// function's tree-sitter node id. `has_function_level_overflow_check_scoped`
    /// re-sanitized (a full AST descendant walk to blank comments/strings) the
    /// same function's text once per risky-operand candidate; on a function
    /// with many candidates that was O(candidates * function_size) = O(n^2).
    /// Cleared at the start of each `check()`, same as `risky_vars_cache`
    /// (task 672).
    function_text_cache: RefCell<HashMap<usize, std::rc::Rc<str>>>,
}

impl Int32C {
    pub fn new() -> Self {
        Self {
            project_macros: RefCell::new(MacroConstantMap::new()),
            current_macros: RefCell::new(MacroConstantMap::new()),
            struct_field_types: RefCell::new(HashMap::new()),
            typedef_types: RefCell::new(HashMap::new()),
            function_macros: RefCell::new(HashMap::new()),
            function_cfgs: RefCell::new(HashMap::new()),
            vra_results: RefCell::new(HashMap::new()),
            function_summaries: RefCell::new(HashMap::new()),
            global_writers: RefCell::new(HashMap::new()),
            risky_vars_cache: RefCell::new(HashMap::new()),
            function_text_cache: RefCell::new(HashMap::new()),
        }
    }

    /// Get VRA-derived variable ranges at a specific expression node,
    /// replaying the containing block up to the expression.
    fn vra_var_ranges_at(&self, expr_node: &Node, source: &str) -> Option<VarRangeMap> {
        vra_access::var_ranges_replay_at(
            &self.function_cfgs.borrow(),
            &self.vra_results.borrow(),
            expr_node,
            source,
            &self.current_macros.borrow(),
        )
    }

    /// Variable ranges to evaluate an expression at `node` with: VRA's
    /// replayed ranges, backed by each narrow-typed variable's promoted-type
    /// range wherever VRA has nothing more precise.
    ///
    /// The backing is what lets the range engine reach a verdict on `char c,
    /// char d` parameters at all. Without it `c + d` is simply unresolvable,
    /// so [`const_eval::expression_fits_in_signed_vra`] cannot prove the
    /// thing promotion guarantees, and the expression falls through to the
    /// provenance gate -- which fires on an unresolved operand by design
    /// (task 926).
    ///
    /// `type_map` is already function-scoped by `check_node`, so a name that
    /// is `char` in one function and `int` in another does not leak a bogus
    /// range across the boundary. VRA wins wherever it has an entry: its
    /// range is flow-sensitive and never wider than the declared type's.
    fn value_ranges_at(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> Option<VarRangeMap> {
        let vra = self.vra_var_ranges_at(node, source);
        let mut ranges: VarRangeMap = type_map
            .iter()
            .filter_map(|(name, declared)| {
                const_eval::promoted_range_for_type(declared).map(|r| (name.clone(), r))
            })
            .collect();
        if ranges.is_empty() {
            return vra;
        }
        if let Some(vra) = vra {
            ranges.extend(vra);
        }
        Some(ranges)
    }
}

impl CertRule for Int32C {
    fn rule_id(&self) -> &'static str {
        "INT32-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that operations on signed integers do not result in overflow"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "INT32-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_macros.borrow_mut() = context.macro_constants.clone();
        *self.struct_field_types.borrow_mut() = context.struct_field_types.clone();
        *self.typedef_types.borrow_mut() = context.typedef_types.clone();
        *self.function_macros.borrow_mut() = context.function_macros.clone();
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.global_writers.borrow_mut() = context.global_writers.clone();
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
        let type_map = self.collect_variable_types(node, source);

        // Merge project-level macros with per-file macros (per-file wins)
        *self.current_macros.borrow_mut() =
            const_eval::merged_macro_constants(&self.project_macros.borrow(), node, source);

        // Risky-var memo is keyed on tree-sitter node ids, which are only unique
        // within a single parse tree — reset it for each file.
        self.risky_vars_cache.borrow_mut().clear();
        self.function_text_cache.borrow_mut().clear();

        self.check_node(node, source, &mut violations, &type_map);
        violations
    }
}

impl Int32C {
    fn check_node(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        let candidates = query::find_descendants_of_kinds(
            *node,
            &[
                "binary_expression",
                "assignment_expression",
                "unary_expression",
                "update_expression",
                "call_expression",
            ],
        );

        // Scope type_map per function to avoid cross-function name collisions
        // (e.g., float X_pred in one function vs int32_t X_pred in another).
        // Memoized per enclosing function_definition node id so it's only
        // computed once even though many candidates share the same function.
        let mut fn_type_maps: HashMap<usize, HashMap<String, String>> = HashMap::new();

        for candidate in candidates {
            // Skip nodes inside compile-time contexts (cannot overflow at runtime)
            if self.is_in_compile_time_context(&candidate) {
                continue;
            }

            let scoped_type_map: &HashMap<String, String> =
                match overflow_helpers::enclosing_function_definition(&candidate) {
                    Some(func_node) => fn_type_maps
                        .entry(func_node.id())
                        .or_insert_with(|| self.collect_variable_types(&func_node, source)),
                    None => type_map,
                };

            match candidate.kind() {
                "binary_expression" => {
                    self.check_binary_operation(&candidate, source, violations, scoped_type_map);
                }
                "assignment_expression" => {
                    self.check_assignment_operation(
                        &candidate,
                        source,
                        violations,
                        scoped_type_map,
                    );
                }
                "unary_expression" => {
                    self.check_unary_operation(&candidate, source, violations, scoped_type_map);
                }
                "update_expression" => {
                    self.check_increment_decrement(&candidate, source, violations, scoped_type_map);
                }
                "call_expression" => {
                    self.check_function_call(&candidate, source, violations, scoped_type_map);
                }
                _ => {}
            }
        }
    }

    /// Check if this node is inside a compile-time context where overflow cannot occur at runtime.
    /// Covers: sizeof(), _Static_assert, enum value definitions, array size declarators.
    fn is_in_compile_time_context(&self, node: &Node) -> bool {
        let mut current = node.parent();
        while let Some(parent) = current {
            match parent.kind() {
                "sizeof_expression" => return true,
                "static_assert_declaration" => return true,
                "enumerator" => return true,
                "array_declarator" => {
                    // Array size expressions like int arr[N + 1] are compile-time
                    return true;
                }
                "function_definition" => break,
                _ => {}
            }
            current = parent.parent();
        }
        false
    }

    /// For compound assignments (`x op= y`), check if `x op y` provably fits
    /// in a signed integer of `bits` width using constant evaluation.
    /// Note: only resolves the RHS — the LHS is the mutation target and its
    /// initial assignment doesn't reflect its current value (especially in loops).
    fn compound_expr_fits_signed(&self, node: &Node, source: &str, op: &str, bits: u32) -> bool {
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
            let lr = const_eval::try_evaluate_range(&left, source, &macros, &loop_ranges);
            let rr = const_eval::try_evaluate_range(&right, source, &macros, &var_ranges);
            if let (Some(lr), Some(rr)) = (lr, rr) {
                let result = match op {
                    "+" => lr.add(&rr),
                    "-" => lr.sub(&rr),
                    "*" => lr.mul(&rr),
                    "<<" => lr.shl(&rr),
                    _ => None,
                };
                if let Some(range) = result {
                    return range.fits_in_signed(bits);
                }
            }
        }
        false
    }

    fn check_binary_operation(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        // INT32-C concerns signed INTEGER overflow (UB). C's usual arithmetic
        // conversions promote the whole expression to float/double the moment
        // either operand is float-typed, at which point overflow saturates to
        // inf rather than wrapping/UB — so skip float-typed operations
        // entirely, matching INT33-C's division_is_floating gate.
        if self.operands_are_floating(node, source, type_map) {
            return;
        }

        if let Some(operator) = self.get_operator(node, source) {
            match operator.as_str() {
                "+" => self.check_addition(node, source, violations, type_map),
                "-" => self.check_subtraction(node, source, violations, type_map),
                "*" => self.check_multiplication(node, source, violations, type_map),
                "/" => self.check_division(node, source, violations, type_map),
                "%" => self.check_modulo(node, source, violations, type_map),
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
    ) {
        // See check_binary_operation: skip compound assignments whose operand
        // types make this floating-point arithmetic, not integer overflow.
        if self.operands_are_floating(node, source, type_map) {
            return;
        }

        if let Some(operator) = self.get_assignment_operator(node, source) {
            match operator.as_str() {
                "+=" => self.check_compound_addition(node, source, violations, type_map),
                "-=" => self.check_compound_subtraction(node, source, violations, type_map),
                "*=" => self.check_compound_multiplication(node, source, violations, type_map),
                "/=" => self.check_compound_division(node, source, violations),
                "%=" => self.check_compound_modulo(node, source, violations),
                "<<=" => self.check_compound_left_shift(node, source, violations, type_map),
                _ => {}
            }
        }
    }

    fn check_unary_operation(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        if let Some(operator) = self.get_unary_operator(node, source) {
            if operator == "-" {
                // See check_binary_operation: `-x` on a float-typed operand
                // isn't the -INT_MIN overflow INT32-C covers.
                if let Some(argument) = node.child_by_field_name("argument") {
                    if self.expr_is_float(&argument, source, type_map) {
                        return;
                    }
                }
                self.check_negation(node, source, violations, type_map);
            }
        }
    }

    /// Best-effort: does this expression have floating-point type? Delegates
    /// to the shared [`float_typing`] engine, supplying INT32-C's struct
    /// field map.
    fn expr_is_float(&self, node: &Node, source: &str, type_map: &HashMap<String, String>) -> bool {
        let sft = self.struct_field_types.borrow();
        float_typing::expr_is_float(node, source, type_map, &sft)
    }

    /// True if `node`'s left or right operand is float-typed, making this a
    /// floating-point operation rather than the integer arithmetic INT32-C
    /// covers. Shared by [`check_binary_operation`] and
    /// [`check_assignment_operation`], both of which have `left`/`right`
    /// fields.
    fn operands_are_floating(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        if let Some(l) = node.child_by_field_name("left") {
            if self.expr_is_float(&l, source, type_map) {
                return true;
            }
        }
        if let Some(r) = node.child_by_field_name("right") {
            if self.expr_is_float(&r, source, type_map) {
                return true;
            }
        }
        false
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

            // Skip if any operand is a non-integer type (char, float, pointer, etc.)
            if left_type == "not_applicable" || right_type == "not_applicable" {
                return;
            }

            // Skip if either operand is unsigned — unsigned wrap is INT30-C, not INT32-C
            if left_type == "unsigned" || right_type == "unsigned" {
                return;
            }

            if self.is_signed_type(&left_type) || self.is_signed_type(&right_type) {
                // Skip if this operation is part of an overflow check comparison
                if self.is_part_of_comparison(node, source) {
                    return;
                }

                // Opt-in provenance gate: only flag when an operand derives
                // from untrusted/unbounded input. Bounded local state (counters,
                // indices, struct-field counts) cannot reach the type limit here.
                if !self.has_risky_operand_provenance(node, source, type_map) {
                    return;
                }

                // Skip if using wider type (cast to long long before addition)
                let left_text = get_node_text(&left, source);
                let right_text = get_node_text(&right, source);
                if self.has_wider_cast(left_text, right_text) {
                    return;
                }

                // Skip if inside a block guarded by a type-limit bounds check
                let op_names = self.extract_operand_names(node, source);
                if self.is_inside_bounds_checked_block(node, source, &op_names) {
                    return;
                }

                // Skip if constant evaluation proves the result fits where it
                // lands. An unresolved destination proves nothing, so it does
                // not skip.
                if self.result_fits_destination(node, source, type_map) {
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

                if !self.has_overflow_check_addition(node, source) {
                    let start_point = node.start_position();
                    let expr_text = get_node_text(node, source);

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Signed integer addition '{}' may overflow without proper checking",
                            expr_text
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Add overflow check: if ((b > 0 && a > INT_MAX - b) || (b < 0 && a < INT_MIN - b)) { /* handle error */ }".to_string()),
                    ..Default::default()
                    });
                }
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

            // Skip if any operand is a non-integer type (char, float, pointer, etc.)
            if left_type == "not_applicable" || right_type == "not_applicable" {
                return;
            }

            // Skip if either operand is unsigned — unsigned wrap is INT30-C, not INT32-C
            if left_type == "unsigned" || right_type == "unsigned" {
                return;
            }

            if self.is_signed_type(&left_type) || self.is_signed_type(&right_type) {
                // Skip if this operation is part of an overflow check comparison
                if self.is_part_of_comparison(node, source) {
                    return;
                }

                // Skip if both operands are constants (compiler handles these)
                let left_text = get_node_text(&left, source);
                let right_text = get_node_text(&right, source);
                if self.is_constant_expression(left_text) && self.is_constant_expression(right_text)
                {
                    return; // Safe - constant expression
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(node, source, type_map) {
                    return;
                }

                // Skip if using wider type (cast to long long before subtraction)
                if self.has_wider_cast(left_text, right_text) {
                    return;
                }

                // Skip if inside a block guarded by a type-limit bounds check
                let op_names = self.extract_operand_names(node, source);
                if self.is_inside_bounds_checked_block(node, source, &op_names) {
                    return;
                }

                // Skip if constant evaluation proves the result fits where it
                // lands. An unresolved destination proves nothing, so it does
                // not skip.
                if self.result_fits_destination(node, source, type_map) {
                    return;
                }

                if !self.has_overflow_check_subtraction(node, source) {
                    let start_point = node.start_position();
                    let expr_text = get_node_text(node, source);

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Signed integer subtraction '{}' may overflow without proper checking",
                            expr_text
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Add overflow check: if ((b < 0 && a > INT_MAX + b) || (b > 0 && a < INT_MIN + b)) { /* handle error */ }".to_string()),
                    ..Default::default()
                    });
                }
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
            let left_type = self.infer_type(&left, source, type_map);
            let right_type = self.infer_type(&right, source, type_map);

            // Skip if any operand is a non-integer type (char, float, pointer, etc.)
            if left_type == "not_applicable" || right_type == "not_applicable" {
                return;
            }

            // Skip if either operand is unsigned — unsigned wrap is INT30-C, not INT32-C
            if left_type == "unsigned" || right_type == "unsigned" {
                return;
            }

            if self.is_signed_type(&left_type) || self.is_signed_type(&right_type) {
                // Skip if this operation is part of an overflow check comparison
                if self.is_part_of_comparison(node, source) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(node, source, type_map) {
                    return;
                }

                // Skip if using wider type (cast to long long before multiplication)
                let left_text = get_node_text(&left, source);
                let right_text = get_node_text(&right, source);
                if self.has_wider_cast(left_text, right_text) {
                    return; // Safe - using wider type
                }

                // Skip if operands are bounded for-loop variables
                if self.is_in_bounded_for_loop(node, source) {
                    return;
                }

                // Skip if inside a block guarded by a type-limit bounds check
                let op_names = self.extract_operand_names(node, source);
                if self.is_inside_bounds_checked_block(node, source, &op_names) {
                    return;
                }

                // Skip if constant evaluation proves the result fits where it
                // lands. An unresolved destination proves nothing, so it does
                // not skip.
                if self.result_fits_destination(node, source, type_map) {
                    return;
                }

                if !self.has_overflow_check_multiplication(node, source) {
                    let start_point = node.start_position();
                    let expr_text = get_node_text(node, source);

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Signed integer multiplication '{}' may overflow without proper checking",
                            expr_text
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Add overflow check using complex multiplication overflow detection".to_string()),
                    ..Default::default()
                    });
                }
            }
        }
    }

    fn check_division(
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
            let left_text = get_node_text(&left, source);
            let right_text = get_node_text(&right, source);
            let left_type = self.infer_type(&left, source, type_map);
            let right_type = self.infer_type(&right, source, type_map);

            // Skip if any operand is a non-integer type (char, float, pointer, etc.)
            if left_type == "not_applicable" || right_type == "not_applicable" {
                return;
            }

            // Skip if either operand is unsigned — unsigned wrap is INT30-C, not INT32-C
            if left_type == "unsigned" || right_type == "unsigned" {
                return;
            }

            // Check for signed integer division
            // INT_MIN / -1 causes overflow because -INT_MIN cannot be represented
            if self.is_signed_type(&left_type) || self.is_signed_type(&right_type) {
                // Skip if this division is part of an overflow check comparison
                if self.is_part_of_comparison(node, source) {
                    return;
                }

                // Check if there's explicit INT_MIN/-1 pattern OR generic signed division without checks
                let has_explicit_risk = right_text.trim() == "-1"
                    || right_text.contains("-1")
                    || left_text.contains("INT_MIN")
                    || left_text.contains("LONG_MIN")
                    || self.could_be_int_min(&left, source);

                // Also flag generic signed division of variables (could be INT_MIN / -1 at runtime)
                // but skip if the right operand (divisor) is unsigned — can't be -1.
                // Opt-in provenance gate: a bounded local divisor cannot be -1
                // and a bounded dividend cannot be INT_MIN, so require risky
                // provenance for the generic (non-literal) case.
                let is_variable_division = left.kind() == "identifier"
                    && right.kind() == "identifier"
                    && !self.is_unsigned_type(&right_type)
                    && self.has_risky_operand_provenance(node, source, type_map);

                if (has_explicit_risk || is_variable_division)
                    && !self.has_division_overflow_check(node, source)
                {
                    let start_point = node.start_position();
                    let expr_text = get_node_text(node, source);

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Signed integer division '{}' may overflow (INT_MIN / -1)",
                            expr_text
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Add check: if (dividend == INT_MIN && divisor == -1) { /* handle error */ }".to_string()),
                    ..Default::default()
                    });
                }
            }
        }
    }

    fn check_modulo(
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
            let left_text = get_node_text(&left, source);
            let right_text = get_node_text(&right, source);
            let left_type = self.infer_type(&left, source, type_map);
            let right_type = self.infer_type(&right, source, type_map);

            // Skip if any operand is a non-integer type (char, float, pointer, etc.)
            if left_type == "not_applicable" || right_type == "not_applicable" {
                return;
            }

            // Skip if either operand is unsigned — unsigned wrap is INT30-C, not INT32-C
            if left_type == "unsigned" || right_type == "unsigned" {
                return;
            }

            // Check for signed integer modulo
            // INT_MIN % -1 causes overflow
            if self.is_signed_type(&left_type) || self.is_signed_type(&right_type) {
                let has_explicit_risk = (left_text.contains("INT_MIN")
                    || left_text.contains("LONG_MIN")
                    || self.could_be_int_min(&left, source))
                    && (right_text == "-1" || right_text.contains("-1"));

                // Also flag generic signed modulo of variables (could be INT_MIN % -1 at runtime)
                // but skip if the right operand (divisor) is unsigned — can't be -1.
                // Opt-in provenance gate (see check_division).
                let is_variable_modulo = left.kind() == "identifier"
                    && right.kind() == "identifier"
                    && !self.is_unsigned_type(&right_type)
                    && self.has_risky_operand_provenance(node, source, type_map);

                if (has_explicit_risk || is_variable_modulo)
                    && !self.has_modulo_overflow_check(node, source)
                {
                    let start_point = node.start_position();
                    let expr_text = get_node_text(node, source);

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Signed integer modulo '{}' may overflow (INT_MIN % -1)",
                            expr_text
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Add check: if (dividend == INT_MIN && divisor == -1) { /* handle error */ }".to_string()),
                    ..Default::default()
                    });
                }
            }
        }
    }

    fn check_negation(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        if let Some(argument) = node.child_by_field_name("argument") {
            let _arg_text = get_node_text(&argument, source);
            let arg_type = self.infer_type(&argument, source, type_map);

            // Skip if operand is a non-integer type (char, float, pointer, etc.)
            if arg_type == "not_applicable" {
                return;
            }

            // Check for negation of signed integers, especially -INT_MIN which causes overflow.
            // Opt-in provenance gate: only INT_MIN negates to overflow, which a
            // bounded local operand cannot reach.
            if self.is_signed_type(&arg_type)
                && self.has_risky_operand_provenance(node, source, type_map)
                && !self.has_negation_overflow_check(node, source)
            {
                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Signed integer negation '{}' may overflow (-INT_MIN)",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Add check: if (value == INT_MIN) { /* handle error */ }".to_string(),
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

            // Skip if operand is a non-integer type (char, float, pointer, etc.)
            if left_type == "not_applicable" {
                return;
            }

            if self.is_signed_type(&left_type) {
                // Skip if inside a block guarded by a type-limit bounds check
                let op_names = self.extract_operand_names(node, source);
                if self.is_inside_bounds_checked_block(node, source, &op_names) {
                    return;
                }

                // Skip if constant evaluation proves the result fits where it
                // lands. An unresolved destination proves nothing, so it does
                // not skip.
                if self.result_fits_destination(node, source, type_map) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(node, source, type_map) {
                    return;
                }

                if !self.has_shift_overflow_check(node, source) {
                    let start_point = node.start_position();
                    let expr_text = get_node_text(node, source);

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Signed integer left shift '{}' may overflow or exhibit undefined behavior",
                            expr_text
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Validate shift amount and check for overflow before shifting".to_string()),
                    ..Default::default()
                    });
                }
            }
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

            // Skip if operand is a non-integer type (char, float, pointer, etc.)
            if left_type == "not_applicable" {
                return;
            }

            if self.is_signed_type(&left_type) {
                // Skip if inside a block guarded by a type-limit bounds check
                let op_names = self.extract_operand_names(node, source);
                if self.is_inside_bounds_checked_block(node, source, &op_names) {
                    return;
                }

                // Skip if constant evaluation proves the result fits back in the
                // assignment target, which is where the promoted result lands
                let vra_bits = Self::stored_type_bits(&left_type);
                if self.compound_expr_fits_signed(node, source, "+", vra_bits) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(node, source, type_map) {
                    return;
                }

                if !self.has_overflow_check_compound(node, source) {
                    let start_point = node.start_position();
                    let expr_text = get_node_text(node, source);

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Signed integer compound addition '{}' may overflow without checking",
                            expr_text
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Add overflow check before compound assignment".to_string(),
                        ),
                        ..Default::default()
                    });
                }
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

            // Skip if operand is a non-integer type (char, float, pointer, etc.)
            if left_type == "not_applicable" {
                return;
            }

            if self.is_signed_type(&left_type) {
                // Skip if inside a block guarded by a type-limit bounds check
                let op_names = self.extract_operand_names(node, source);
                if self.is_inside_bounds_checked_block(node, source, &op_names) {
                    return;
                }

                // Skip if constant evaluation proves the result fits back in the
                // assignment target, which is where the promoted result lands
                let vra_bits = Self::stored_type_bits(&left_type);
                if self.compound_expr_fits_signed(node, source, "-", vra_bits) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(node, source, type_map) {
                    return;
                }

                if !self.has_overflow_check_compound(node, source) {
                    let start_point = node.start_position();
                    let expr_text = get_node_text(node, source);

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Signed integer compound subtraction '{}' may overflow without checking",
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

            // Skip if operand is a non-integer type (char, float, pointer, etc.)
            if left_type == "not_applicable" {
                return;
            }

            if self.is_signed_type(&left_type) {
                // Skip if inside a block guarded by a type-limit bounds check
                let op_names = self.extract_operand_names(node, source);
                if self.is_inside_bounds_checked_block(node, source, &op_names) {
                    return;
                }

                // Skip if constant evaluation proves the result fits back in the
                // assignment target, which is where the promoted result lands
                let vra_bits = Self::stored_type_bits(&left_type);
                if self.compound_expr_fits_signed(node, source, "*", vra_bits) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(node, source, type_map) {
                    return;
                }

                if !self.has_overflow_check_compound(node, source) {
                    let start_point = node.start_position();
                    let expr_text = get_node_text(node, source);

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Signed integer compound multiplication '{}' may overflow without checking",
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
    }

    fn check_compound_division(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let left_text = get_node_text(&left, source);
            let right_text = get_node_text(&right, source);

            if (left_text.contains("INT_MIN") || self.could_be_int_min(&left, source))
                && (right_text == "-1" || right_text.contains("-1"))
                && !self.has_overflow_check_compound(node, source)
            {
                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Signed integer compound division '{}' may overflow (INT_MIN /= -1)",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Add check before assignment: if (left == INT_MIN && right == -1) { /* handle error */ }".to_string()),
                    ..Default::default()
                });
            }
        }
    }

    fn check_compound_modulo(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let left_text = get_node_text(&left, source);
            let right_text = get_node_text(&right, source);

            if (left_text.contains("INT_MIN") || self.could_be_int_min(&left, source))
                && (right_text == "-1" || right_text.contains("-1"))
                && !self.has_overflow_check_compound(node, source)
            {
                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Signed integer compound modulo '{}' may overflow (INT_MIN %= -1)",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Add check before assignment: if (left == INT_MIN && right == -1) { /* handle error */ }".to_string()),
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

            // Skip if operand is a non-integer type (char, float, pointer, etc.)
            if left_type == "not_applicable" {
                return;
            }

            if self.is_signed_type(&left_type) {
                // Skip if constant evaluation proves the result fits back in the
                // assignment target, which is where the promoted result lands
                let vra_bits = Self::stored_type_bits(&left_type);
                if self.compound_expr_fits_signed(node, source, "<<", vra_bits) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(node, source, type_map) {
                    return;
                }

                if !self.has_overflow_check_compound(node, source) {
                    let start_point = node.start_position();
                    let expr_text = get_node_text(node, source);

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Signed integer compound left shift '{}' may overflow or exhibit undefined behavior",
                            expr_text
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Validate shift amount and check for overflow before assignment".to_string()),
                        ..Default::default()
                    });
                }
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
        if let Some(argument) = node.child_by_field_name("argument") {
            let arg_type = self.infer_type(&argument, source, type_map);

            // Skip if operand is a non-integer type (char, float, pointer, etc.)
            if arg_type == "not_applicable" {
                return;
            }

            if self.is_signed_type(&arg_type) {
                // Opt-in provenance gate: a bounded counter cannot reach INT_MAX
                // (++) or INT_MIN (--); only an untrusted/unbounded operand can.
                if !self.has_risky_operand_provenance(node, source, type_map) {
                    return;
                }

                // Skip if this is part of a safe for loop (bounded, starting from small values)
                if self.is_in_safe_for_loop(node, source) {
                    return;
                }

                // Skip if inside a block guarded by a type-limit bounds check
                let op_names = self.extract_operand_names(node, source);
                if self.is_inside_bounds_checked_block(node, source, &op_names) {
                    return;
                }

                // Skip if VRA proves the result fits back in the variable being
                // updated, which is where the promoted result lands
                if self.expression_fits_in(
                    node,
                    source,
                    type_map,
                    Self::stored_type_bits(&arg_type),
                ) {
                    return;
                }

                let operator = self.get_update_operator(node, source);
                if (operator == "++" || operator == "--")
                    && !self.has_overflow_check_update(node, source)
                {
                    let start_point = node.start_position();
                    let expr_text = get_node_text(node, source);

                    let message = if operator == "++" {
                        format!(
                            "Signed integer increment '{}' may overflow at INT_MAX",
                            expr_text
                        )
                    } else {
                        format!(
                            "Signed integer decrement '{}' may overflow at INT_MIN",
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

    fn check_function_call(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            // Check for functions that commonly receive arithmetic expressions that might overflow
            match function_name {
                "malloc" | "calloc" | "realloc" => {
                    self.check_allocation_overflow(node, source, function_name, violations);
                }
                "memcpy" | "memmove" | "memset" => {
                    self.check_memory_function_overflow(
                        node,
                        source,
                        function_name,
                        violations,
                        type_map,
                    );
                }
                "abs" | "labs" | "llabs" => {
                    self.check_abs_overflow(node, source, function_name, violations);
                }
                _ => {}
            }
        }
    }

    fn check_allocation_overflow(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(arguments) = node.child_by_field_name("arguments") {
            let mut arg_idx = 0;
            for i in 0..arguments.child_count() {
                if let Some(arg_node) = arguments.child(i) {
                    let kind = arg_node.kind();
                    if kind == "(" || kind == ")" || kind == "," {
                        continue;
                    }

                    // A bare identifier has no arithmetic in its own text
                    // (e.g. `malloc(to_len)`). Walk back one assignment hop
                    // to the statement that computed it -- `to_len =
                    // from_len * 2U + 1U;` -- so that expression gets the
                    // same overflow check an inline `malloc(from_len * 2U +
                    // 1U)` would (task 604).
                    let resolved_rhs = if arg_node.kind() == "identifier" {
                        let var_name = get_node_text(&arg_node, source);
                        ast_utils::find_containing_function(&arg_node)
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

                    let arg_text = get_node_text(check_node, source);
                    if self.contains_arithmetic(arg_text) {
                        // Use const_eval to check if the arithmetic provably fits
                        let macros = self.current_macros.borrow();
                        let vra_ranges = self.vra_var_ranges_at(check_node, source);
                        let fits_64 = const_eval::expression_fits_in_signed_vra(
                            check_node,
                            source,
                            &macros,
                            64,
                            vra_ranges.as_ref(),
                        );
                        // A size argument is computed in size_t. A product that fits
                        // in 64 bits can still *definitely* wrap a 32-bit size_t (the
                        // CWE-680 "data * sizeof(T) > SIZE_MAX" flaw on ILP32): e.g.
                        // a constant `data = INT_MAX/2 + 2` gives `data * sizeof(int)`
                        // = 4294967300 > UINT32_MAX. `expression_overflows_unsigned_vra`
                        // fires only when the whole range exceeds the bound, so legit
                        // small allocations (good `data = 20` -> 80) stay clean.
                        let wraps_32_size_t = const_eval::expression_overflows_unsigned_vra(
                            check_node,
                            source,
                            &macros,
                            32,
                            vra_ranges.as_ref(),
                        );
                        if fits_64 && !wraps_32_size_t {
                            arg_idx += 1;
                            continue;
                        }
                        drop(macros);
                        if !self.has_allocation_overflow_check(node, source) {
                            let start_point = node.start_position();
                            let message = if resolved_rhs.is_some() {
                                format!(
                                    "{}() argument {} ('{}') was computed by arithmetic that may overflow: '{}'",
                                    function_name,
                                    arg_idx + 1,
                                    get_node_text(&arg_node, source),
                                    arg_text
                                )
                            } else {
                                format!(
                                    "{}() argument {} contains arithmetic that may overflow: '{}'",
                                    function_name,
                                    arg_idx + 1,
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
                                    "Validate arithmetic operations before passing to allocation functions"
                                        .to_string(),
                                ),
                                ..Default::default()
                            });
                        }
                    }
                    arg_idx += 1;
                }
            }
        }
    }

    fn check_memory_function_overflow(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        // Check size arguments for arithmetic that might overflow
        let size_arg_idx: usize = match function_name {
            "memcpy" | "memmove" | "memset" => 2, // Third argument is size
            _ => return,
        };

        if let Some(arguments) = node.child_by_field_name("arguments") {
            let mut arg_idx = 0;
            for i in 0..arguments.child_count() {
                if let Some(arg_node) = arguments.child(i) {
                    let kind = arg_node.kind();
                    if kind == "(" || kind == ")" || kind == "," {
                        continue;
                    }
                    if arg_idx == size_arg_idx {
                        // Simple field access (e.g., struct->field) is not arithmetic.
                        // contains_arithmetic() text match hits '->' as '-'.
                        if arg_node.kind() == "field_expression" {
                            return;
                        }
                        // sizeof(...) always yields size_t, no signed overflow.
                        // contains_arithmetic() false-matches the `*` in `sizeof(*ctx)`.
                        if arg_node.kind() == "sizeof_expression" {
                            return;
                        }
                        // This checker is otherwise purely text/VRA-shape-based and
                        // never consults the declared-type map, so a genuinely
                        // unsigned size computation (a word_t/paddr_t-typedef-family
                        // struct-field subtraction, e.g. seL4's `ui_p_regs.end -
                        // ui_p_regs.start`) had no way to be recognized as safe --
                        // wrap-on-negative there is well-defined unsigned behavior,
                        // not an INT32-C concern. Reuses the same declared-type
                        // classification (now typedef-chain-aware) the other
                        // arithmetic checks already use (task 657).
                        if arg_node.kind() == "binary_expression"
                            && self.infer_type(&arg_node, source, type_map) == "unsigned"
                        {
                            return;
                        }
                        let arg_text = get_node_text(&arg_node, source);
                        if self.contains_arithmetic(arg_text) {
                            // Use const_eval to check if the arithmetic provably fits
                            let macros = self.current_macros.borrow();
                            let vra_ranges = self.vra_var_ranges_at(&arg_node, source);
                            if const_eval::expression_fits_in_signed_vra(
                                &arg_node,
                                source,
                                &macros,
                                64,
                                vra_ranges.as_ref(),
                            ) {
                                return;
                            }
                            drop(macros);
                            if !self.has_memory_function_overflow_check(node, source) {
                                let start_point = node.start_position();
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::High,
                                    message: format!(
                                        "{}() size argument contains arithmetic that may overflow: '{}'",
                                        function_name, arg_text
                                    ),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some(
                                        "Validate size calculations before passing to memory functions"
                                            .to_string(),
                                    ),
                                    ..Default::default()
                                });
                            }
                        }
                        return;
                    }
                    arg_idx += 1;
                }
            }
        }
    }

    fn check_abs_overflow(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // abs(INT_MIN), labs(LONG_MIN), llabs(LLONG_MIN) all cause overflow
        // because the absolute value of the minimum signed integer cannot be represented

        // Skip if the abs() argument is cast to a wider type (e.g., abs((long)data)).
        // Widening cast means the minimum value of the original type is representable
        // in the wider type's abs range, so overflow can't occur.
        if self.abs_arg_has_widening_cast(node, source, function_name) {
            return;
        }

        // Skip if abs() call is part of a comparison condition (it IS a bounds check).
        // Pattern: if (abs(x) <= limit) { ... } — the abs() is the safety check itself.
        if self.is_inside_comparison_condition(node) {
            return;
        }

        if !self.has_abs_overflow_check(node, source) {
            let start_point = node.start_position();
            let expr_text = get_node_text(node, source);

            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "{}() may overflow when called with most negative value (e.g., INT_MIN): '{}'",
                    function_name, expr_text
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some("Check if argument equals INT_MIN/LONG_MIN/LLONG_MIN before calling abs/labs/llabs".to_string()),
            ..Default::default()
            });
        }
    }

    /// Check if the abs() argument contains a widening cast (e.g., `abs((long)data)`).
    /// When abs() gets `int` but is called as `abs((long)data)`, the long range
    /// means INT_MIN cast to long is representable and abs() won't overflow.
    fn abs_arg_has_widening_cast(&self, node: &Node, source: &str, function_name: &str) -> bool {
        if let Some(arguments) = node.child_by_field_name("arguments") {
            for i in 0..arguments.child_count() {
                if let Some(arg) = arguments.child(i) {
                    if arg.kind() == "cast_expression" {
                        let cast_text = get_node_text(&arg, source);
                        // For abs(): widening to long or long long
                        if function_name == "abs"
                            && (cast_text.contains("(long)") || cast_text.contains("(long long)"))
                        {
                            return true;
                        }
                        // For labs(): widening to long long
                        if function_name == "labs" && cast_text.contains("(long long)") {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if this node is inside a comparison that's part of a condition
    /// (e.g., `if (abs(x) <= limit)`).
    fn is_inside_comparison_condition(&self, node: &Node) -> bool {
        let mut current = node.parent();
        let mut depth = 0;
        while let Some(parent) = current {
            if depth > 10 {
                break;
            }
            match parent.kind() {
                "binary_expression" => {
                    // Check if this is a comparison operator
                    for i in 0..parent.child_count() {
                        if let Some(c) = parent.child(i) {
                            if matches!(c.kind(), "<" | "<=" | ">" | ">=" | "==" | "!=") {
                                // Now check if the comparison is part of an if/while condition
                                if let Some(grandparent) = parent.parent() {
                                    if grandparent.kind() == "parenthesized_expression" {
                                        if let Some(ggp) = grandparent.parent() {
                                            if matches!(
                                                ggp.kind(),
                                                "if_statement" | "while_statement"
                                            ) {
                                                return true;
                                            }
                                        }
                                    }
                                    // Also handle: if (abs(x) <= y && ...)
                                    if matches!(grandparent.kind(), "binary_expression") {
                                        if let Some(ggp) = grandparent.parent() {
                                            if ggp.kind() == "parenthesized_expression" {
                                                if let Some(gggp) = ggp.parent() {
                                                    if matches!(
                                                        gggp.kind(),
                                                        "if_statement" | "while_statement"
                                                    ) {
                                                        return true;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                return false;
                            }
                        }
                    }
                }
                "function_definition" | "translation_unit" => break,
                _ => {}
            }
            current = parent.parent();
            depth += 1;
        }
        false
    }

    /// Collect variable types from function parameters and local declarations.
    /// Walks the entire AST to find all function_definition nodes and collects
    /// types from their parameters and body declarations.
    fn collect_variable_types(&self, node: &Node, source: &str) -> HashMap<String, String> {
        overflow_helpers::collect_variable_types(node, source)
    }

    fn infer_type(&self, node: &Node, source: &str, type_map: &HashMap<String, String>) -> String {
        let text = get_node_text(node, source);

        // Check the type map FIRST — most reliable source of type info.
        // Must come before text heuristics because variable names like "index"
        // contain "int" as a substring, causing false signed classification.
        if node.kind() == "identifier" {
            if let Some(declared_type) = type_map.get(text) {
                return self.classify_declared_type(declared_type);
            }
        }

        if let Some(t) = Self::infer_type_from_unsigned_literal_text(text) {
            return t;
        }

        // Call-like operand invoking a function-like macro (e.g. seL4's
        // `BIT(n)` -> `(UL_CONST(1) << (n))`): sqc has no preprocessor, so
        // this looked like an ordinary unresolvable call and fell through
        // to "unknown", making a signed-looking operand on the other side
        // of `-`/`+` look risky even though the macro's own definition
        // makes the result an unsigned constant (task 676).
        if node.kind() == "call_expression" {
            if let Some(t) = self.infer_type_from_macro_call(node, source) {
                return t;
            }
        }

        // Field expressions (e.g., s->count): try to resolve via struct field type database
        if node.kind() == "field_expression" {
            return self.infer_field_expression_type(node, source, type_map);
        }

        // Binary expressions: propagate unsigned/not_applicable from sub-operands.
        if node.kind() == "binary_expression" {
            if let Some(t) = self.infer_binary_expression_type(node, source, type_map) {
                return t;
            }
        }

        if let Some(t) = Self::infer_type_from_keyword_text(node, text) {
            return t;
        }

        // Fall back to old heuristic for variable names not in the type map
        if text.chars().all(|c| c.is_ascii_alphabetic() || c == '_') {
            if let Some(declared_type) = self.find_variable_declaration(node, source, text) {
                return declared_type;
            }
        }

        if let Some(t) = Self::infer_type_from_identifier_name(text) {
            return t;
        }

        // For variables NOT in the type map, default to unknown instead of signed
        // This prevents false positives on variables whose type we can't determine
        "unknown".to_string()
    }

    /// If `node` (a `call_expression`) invokes a known function-like macro
    /// that yields an unsigned constant, per
    /// [`Self::macro_yields_unsigned_constant`], classify it `"unsigned"`.
    /// Otherwise `None` (fall through to the rest of `infer_type`'s chain).
    fn infer_type_from_macro_call(&self, node: &Node, source: &str) -> Option<String> {
        let func = node.child_by_field_name("function")?;
        if func.kind() != "identifier" {
            return None;
        }
        let name = get_node_text(&func, source);
        let macros = self.function_macros.borrow();
        if Self::is_unsigned_constant_helper_name(name)
            || Self::macro_yields_unsigned_constant(&macros, name, 4)
        {
            return Some("unsigned".to_string());
        }
        None
    }

    /// Names of well-known "make this an unsigned constant" helper macros —
    /// the standard idiom (also seen as `_UL`/`_AC(x, UL)` in the Linux
    /// kernel; seL4's own `util.h` names them `UL_CONST`/`ULL_CONST`) for
    /// defining an integer literal with a specific unsigned suffix via
    /// token-pasting (`PASTE(x, ul)` -> `1ul`) so the same header also
    /// parses under a raw assembler (`#define UL_CONST(x) x`, no suffix,
    /// under `#ifdef __ASSEMBLER__`). sqc has no preprocessor and never
    /// expands `#`/`##` (`macro_expand`'s deliberate scope cut — real cpp
    /// semantics needed), and its "first `#define` wins" tie-break across
    /// `#ifdef` branches happens to pick the assembler branch here (it's
    /// textually first), which would otherwise misclassify the constant as
    /// plain (signed) `int`. Recognized by name instead: whichever branch
    /// sqc's macro table resolved to, invoking a macro with one of these
    /// names is-by-convention always meant to produce an unsigned value in
    /// every real (non-assembler) C translation unit -- the only kind sqc
    /// ever scans.
    fn is_unsigned_constant_helper_name(name: &str) -> bool {
        matches!(
            name,
            "UL_CONST" | "ULL_CONST" | "U_CONST" | "UINT_CONST" | "U64_CONST"
        )
    }

    /// True if `name`'s own definition in `macros` directly, or
    /// transitively through nested macro calls it invokes (bounded by
    /// `depth`), invokes a macro matching
    /// [`Self::is_unsigned_constant_helper_name`]. Pure text scan over
    /// already-collected macro bodies (`FunctionMacro.body`) -- doesn't
    /// need full parameter substitution/rescanning since only the STATIC
    /// structure of which macro calls which matters here, not any
    /// particular call site's actual argument values (e.g. seL4's `BIT(n)`
    /// = `(UL_CONST(1) << (n))` is unsigned for every `n`, and `MASK(n)` =
    /// `(BIT(n) - UL_CONST(1))` transitively so via `BIT`).
    fn macro_yields_unsigned_constant(
        macros: &HashMap<String, FunctionMacro>,
        name: &str,
        depth: u32,
    ) -> bool {
        if depth == 0 {
            return false;
        }
        let Some(m) = macros.get(name) else {
            return false;
        };
        for tok in Self::call_like_identifier_tokens(&m.body) {
            if Self::is_unsigned_constant_helper_name(&tok) {
                return true;
            }
            if tok != name
                && macros.contains_key(&tok)
                && Self::macro_yields_unsigned_constant(macros, &tok, depth - 1)
            {
                return true;
            }
        }
        false
    }

    /// Every identifier token in `text` that is immediately followed
    /// (ignoring whitespace) by `(` -- i.e. looks like a macro/function
    /// call site within a macro's replacement-list text.
    fn call_like_identifier_tokens(text: &str) -> Vec<String> {
        let chars: Vec<char> = text.chars().collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < chars.len() {
            if chars[i].is_ascii_alphabetic() || chars[i] == '_' {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let mut j = i;
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                if j < chars.len() && chars[j] == '(' {
                    out.push(chars[start..i].iter().collect());
                }
            } else {
                i += 1;
            }
        }
        out
    }

    /// Classify a resolved declared-type string (from the type map or a
    /// struct field database) into INT32-C's signedness/width bucket.
    /// Narrow signed types are tracked distinctly (`char`/`short`) so VRA
    /// checks use their actual bit width; non-integer types are
    /// `not_applicable`.
    fn classify_declared_type(&self, declared_type: &str) -> String {
        if self.is_unsigned_type(declared_type) {
            return "unsigned".to_string();
        }
        // `declared_type` is the alias name exactly as written (e.g.
        // "word_t", "paddr_t") -- `is_unsigned_type` only recognizes it
        // directly if it happens to spell out "unsigned"/"uint"/"size_t".
        // Resolve the full, possibly multi-level and cross-file typedef
        // chain before falling through to the signed/not_applicable
        // guesses below (task 657).
        if overflow_helpers::typedef_chain_is_unsigned(declared_type, &self.typedef_types.borrow())
        {
            return "unsigned".to_string();
        }
        if declared_type == "int8_t" {
            return "char".to_string();
        }
        if declared_type == "int16_t" || declared_type.contains("short") {
            return "short".to_string();
        }
        // Only return signed if the type is clearly an integer type
        if declared_type.contains("int")
            || declared_type.contains("long")
            || declared_type == "signed"
        {
            return "signed".to_string();
        }
        // char is a signed integer type (on most platforms); tracked
        // distinctly so `stored_type_bits` can tell how wide a *destination*
        // it makes -- never how wide the arithmetic is (that is always
        // `PROMOTED_ARITH_BITS`; see `result_width_bits`).
        if declared_type == "char" || declared_type == "signed char" {
            return "char".to_string();
        }
        // Non-integer types (float, double, pointers, structs) — not applicable to INT32-C
        "not_applicable".to_string()
    }

    /// Explicit unsigned-type/literal text markers, applicable regardless of node kind.
    fn infer_type_from_unsigned_literal_text(text: &str) -> Option<String> {
        // Look for explicit unsigned type indicators
        if text.contains("unsigned") || text.contains("size_t") || text.contains("uint") {
            return Some("unsigned".to_string());
        }
        // Look for unsigned literals
        if text.ends_with('u') || text.ends_with('U') {
            return Some("unsigned".to_string());
        }
        // Look for unsigned constants
        if text.contains("UINT_MAX") || text.contains("SIZE_MAX") {
            return Some("unsigned".to_string());
        }
        None
    }

    /// `field_expression` case (e.g., `s->count`): resolve via the struct
    /// field type database, else `not_applicable`.
    fn infer_field_expression_type(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> String {
        let sft = self.struct_field_types.borrow();
        match crate::utility::cert_c::ast_utils::resolve_field_expression_type(
            node, source, type_map, &sft,
        ) {
            Some(field_type) => self.classify_declared_type(&field_type),
            None => "not_applicable".to_string(),
        }
    }

    /// `binary_expression` case: propagate unsigned/not_applicable from
    /// sub-operands. If any operand in the chain is unsigned, the whole
    /// expression should be treated as unsigned (matching C integer
    /// promotion rules for unsigned types). Returns `None` if either
    /// operand is missing (fall through to the generic text heuristics).
    fn infer_binary_expression_type(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> Option<String> {
        let (left, right) = (
            node.child_by_field_name("left")?,
            node.child_by_field_name("right")?,
        );
        let lt = self.infer_type(&left, source, type_map);
        let rt = self.infer_type(&right, source, type_map);
        if lt == "unsigned" || rt == "unsigned" {
            return Some("unsigned".to_string());
        }
        if lt == "not_applicable" || rt == "not_applicable" {
            return Some("not_applicable".to_string());
        }
        if lt == "signed" || rt == "signed" {
            return Some("signed".to_string());
        }
        // Narrow operands promote to int, but the narrow-type annotation is
        // kept so a caller can tell how wide a destination this expression
        // makes when it is itself assigned somewhere.
        if lt == "short" || rt == "short" {
            return Some("short".to_string());
        }
        if lt == "char" || rt == "char" {
            return Some("char".to_string());
        }
        Some("unknown".to_string())
    }

    /// Explicit signed/short keyword and integer-literal text markers
    /// (type specifiers in casts/declarations, and bare numeric literals —
    /// identifiers are handled earlier via the type map).
    fn infer_type_from_keyword_text(node: &Node, text: &str) -> Option<String> {
        if node.kind() != "identifier" && text.contains("short") {
            return Some("short".to_string());
        }
        if node.kind() != "identifier"
            && (text.contains("signed") || text.contains("int") || text.contains("long"))
        {
            return Some("signed".to_string());
        }
        // Look for signed integer constants
        if text.contains("INT_MAX") || text.contains("INT_MIN") {
            return Some("signed".to_string());
        }
        // Plain numbers without unsigned suffix are typically signed
        if text.chars().all(|c| c.is_ascii_digit() || c == '-') {
            return Some("signed".to_string());
        }
        None
    }

    /// Naming-convention fallback for identifiers absent from the type map:
    /// ALL_CAPS macros are unresolvable without expansion, and common
    /// prefixes (`u`/`i`) or substrings (`size`/`len`/`count`/`index`) hint
    /// at signedness.
    fn infer_type_from_identifier_name(text: &str) -> Option<String> {
        // ALL_CAPS identifiers (including those with digits/underscores) are macros whose
        // type cannot be determined without macro expansion. Hardware register addresses
        // (e.g., AFE_INT_EN) look like signed integer literals to the type inference but
        // are actually pointer-width constants. Treat as not_applicable to avoid FPs.
        if !text.is_empty()
            && text
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            return Some("not_applicable".to_string());
        }
        // Variable names that suggest unsigned integers
        if text.starts_with('u') || text.contains("size") || text.contains("len") {
            return Some("unsigned".to_string());
        }
        // Variable names that suggest signed integers
        if text.starts_with('i')
            || text.contains("signed")
            || text.contains("count")
            || text.contains("index")
        {
            return Some("signed".to_string());
        }
        None
    }

    fn find_variable_declaration(
        &self,
        node: &Node,
        source: &str,
        var_name: &str,
    ) -> Option<String> {
        // Look for the function that contains this node
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "function_definition" {
                // Look in function parameters
                if let Some(params) = parent.child_by_field_name("parameters") {
                    // Sanitized so a comment/string literal in the parameter
                    // list can't spoof "unsigned"/"signed" and silently
                    // misclassify a variable's signedness.
                    let params_text = get_sanitized_node_text(&params, source);
                    if params_text.contains("unsigned") && params_text.contains(var_name) {
                        return Some("unsigned".to_string());
                    }
                    if (params_text.contains("signed") || params_text.contains("int"))
                        && params_text.contains(var_name)
                        && !params_text.contains("unsigned")
                    {
                        return Some("signed".to_string());
                    }
                }
                break;
            }
            current = parent.parent();
        }

        // Look in local declarations (simplified)
        current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "declaration" {
                // Sanitized: a comment/string literal inside the declaration
                // (e.g. an initializer) can't spoof "unsigned"/"signed".
                let decl_text = get_sanitized_node_text(&parent, source);
                if decl_text.contains(var_name) {
                    if decl_text.contains("unsigned") {
                        return Some("unsigned".to_string());
                    }
                    if decl_text.contains("signed") || decl_text.contains("int") {
                        return Some("signed".to_string());
                    }
                }
            }
            current = parent.parent();
        }

        None
    }

    fn is_signed_type(&self, type_str: &str) -> bool {
        ast_utils::is_signed_type(type_str)
    }

    /// Storage width of a type as `classify_declared_type` spells it.
    ///
    /// This is the width a *value* is kept at, never the width arithmetic is
    /// performed at -- see [`Self::result_width_bits`].
    fn stored_type_bits(classified_type: &str) -> u32 {
        match classified_type {
            "char" => 8,
            "short" => 16,
            _ => PROMOTED_ARITH_BITS,
        }
    }

    /// True when interval arithmetic proves the result of `node` fits its
    /// destination.
    fn result_fits_destination(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        let bits = self.result_width_bits(node, source, type_map);
        self.expression_fits_in(node, source, type_map, bits)
    }

    /// [`const_eval::expression_fits_in_signed_vra`] over this rule's macro
    /// set and [`Self::value_ranges_at`]'s promoted-range-backed variable
    /// ranges.
    fn expression_fits_in(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
        bits: u32,
    ) -> bool {
        const_eval::expression_fits_in_signed_vra(
            node,
            source,
            &self.current_macros.borrow(),
            bits,
            self.value_ranges_at(node, source, type_map).as_ref(),
        )
    }

    /// The width the result of `node` must be representable in.
    ///
    /// **Not the operands' width.** C's usual arithmetic conversions promote
    /// everything narrower than `int` before the arithmetic runs, so `char +
    /// char` and `short * short` are 32-bit operations, and no `+`, `-` or
    /// `*` over two promoted narrow operands can leave `int` (the widest such
    /// product, `-32768 * -32768`, is under `INT_MAX`). Taking the operands'
    /// declared 8 or 16 bits inverted the premise in both directions at once:
    /// the fits-check refused to skip provably-safe promoted arithmetic, and
    /// the definite-overflow channel of the provenance gate called `short a =
    /// 32000, b = 1000; a + b` a *certain* overflow (task 926).
    ///
    /// What can still lose data is storing that promoted result back into
    /// something narrow -- `short result = data * data`, which is Juliet's
    /// entire CWE-190 `short`/`char` cohort and a real defect. On the letter
    /// of the standard that is a conversion, so INT31-C's; nothing owns it
    /// yet (see the narrow-truncating-store task, which decides the home).
    /// Until something does, INT32-C keeps reporting it, checked against the
    /// destination's width.
    ///
    /// A destination that does not resolve to a narrow integer -- a pointer,
    /// a float, an `int`-or-wider, a name absent from the type map -- gets
    /// [`PROMOTED_ARITH_BITS`], as does every consumer that stores nowhere at
    /// all: a call argument, a comparison, an enclosing expression. Widening
    /// the narrow-destination cases past simple variables and struct fields
    /// (to `buf[i] = a + b`, `*p = a + b`) is deliberately left alone: those
    /// are pervasive in string code, and whether they should fire is the
    /// narrow-truncating-store task's call, not a side effect of this one.
    fn result_width_bits(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> u32 {
        let mut child = *node;
        while let Some(parent) = child.parent() {
            match parent.kind() {
                // Transparent: the value flows straight through.
                "parenthesized_expression" | "comma_expression" => {}
                "cast_expression" => {
                    return match parent.child_by_field_name("type") {
                        Some(t) => self.declared_destination_bits(get_node_text(&t, source)),
                        None => PROMOTED_ARITH_BITS,
                    };
                }
                "init_declarator" => {
                    if parent.child_by_field_name("value").map(|v| v.id()) != Some(child.id()) {
                        return PROMOTED_ARITH_BITS;
                    }
                    return self.declarator_destination_bits(&parent, source);
                }
                "assignment_expression" => {
                    if parent.child_by_field_name("right").map(|v| v.id()) != Some(child.id()) {
                        return PROMOTED_ARITH_BITS;
                    }
                    return match parent.child_by_field_name("left") {
                        Some(lhs) => {
                            Self::stored_type_bits(&self.infer_type(&lhs, source, type_map))
                        }
                        None => PROMOTED_ARITH_BITS,
                    };
                }
                // `return a + b` from a narrow-returning function truncates
                // exactly like a narrow assignment does.
                "return_statement" => {
                    return match ast_utils::find_containing_function(&parent) {
                        Some(func) => self.declarator_destination_bits(&func, source),
                        None => PROMOTED_ARITH_BITS,
                    };
                }
                _ => return PROMOTED_ARITH_BITS,
            }
            child = parent;
        }
        PROMOTED_ARITH_BITS
    }

    /// Destination width for a node carrying a `type` field alongside a
    /// `declarator` -- a `declaration`'s `init_declarator` (via its parent) or
    /// a `function_definition`. A pointer or array declarator makes the
    /// destination a pointer regardless of the base type, so `char *p = q - 8`
    /// stores into a pointer, not into a `char`.
    fn declarator_destination_bits(&self, node: &Node, source: &str) -> u32 {
        let declarator_kind = node
            .child_by_field_name("declarator")
            .map(|d| d.kind().to_string())
            .unwrap_or_default();
        if declarator_kind == "pointer_declarator" || declarator_kind == "array_declarator" {
            return PROMOTED_ARITH_BITS;
        }
        let owner = if node.kind() == "init_declarator" {
            match node.parent() {
                Some(decl) => decl,
                None => return PROMOTED_ARITH_BITS,
            }
        } else {
            *node
        };
        match owner.child_by_field_name("type") {
            Some(t) => self.declared_destination_bits(get_node_text(&t, source)),
            None => PROMOTED_ARITH_BITS,
        }
    }

    /// Storage width of a destination spelled as declared type text. A `*`
    /// anywhere in it makes it a pointer, whose width is not the base type's.
    fn declared_destination_bits(&self, declared_type: &str) -> u32 {
        let declared_type = declared_type.trim();
        if declared_type.contains('*') {
            return PROMOTED_ARITH_BITS;
        }
        Self::stored_type_bits(&self.classify_declared_type(declared_type))
    }

    fn is_unsigned_type(&self, type_str: &str) -> bool {
        type_str == "unsigned"
            || type_str == "size_t"
            || type_str.contains("uint")
            || type_str.starts_with("unsigned ")
            || type_str == "SIZE_MAX"
            || overflow_helpers::is_short_unsigned_typedef(type_str)
    }

    fn could_be_int_min(&self, node: &Node, source: &str) -> bool {
        let text = get_node_text(node, source);
        text.contains("INT_MIN")
            || (text.starts_with("min") && (text.contains("val") || text.contains("num")))
    }

    /// Check if either operand has a wider-type cast (long long), making overflow impossible.
    fn has_wider_cast(&self, left_text: &str, right_text: &str) -> bool {
        let has_ll = |text: &str| {
            text.contains("long long")
                || text.starts_with("(signed long long)")
                || text.starts_with("(long long)")
                || text.starts_with("(int64_t)")
                || text.starts_with("(int_least64_t)")
        };
        has_ll(left_text) || has_ll(right_text)
    }

    /// Extract operand identifier names from a binary expression node.
    /// Returns a vec of variable names found in the left/right operands.
    fn extract_operand_names(&self, node: &Node, source: &str) -> Vec<String> {
        overflow_helpers::extract_operand_names(node, source)
    }

    /// Opt-in provenance gate (task 140).
    ///
    /// Returns true when at least one operand of this arithmetic node derives
    /// from untrusted or unbounded input — a full-range parser (`atoi`,
    /// `strtol`, `rand`, `RAND32`, ...), an environment/IO taint source
    /// (`scanf`, `recv`, `fgets`, ...), a tainted-summary callee return, or a
    /// global written by a tainted function. When this returns false, every
    /// operand is bounded local state (loop counters, register/cursor indices,
    /// struct-field counts, page-size offsets) and the operation is treated as
    /// practically non-overflowing.
    ///
    /// This flips INT32-C from "fire unless proven safe" (opt-out abstract
    /// interpretation) to "fire only when provenance is risky" (opt-in taint),
    /// matching precision-oriented tools (ELAID, the Clang taint checker) and
    /// eliminating the bounded-counter false positives that dominate hardened
    /// codebases such as SQLite.
    ///
    /// Signed width this operation is checked against, matching what each
    /// `check_*` site computes for its VRA check: `min` of the two operand
    /// widths for binary ops, the single operand width for unary/compound ops.
    fn operand_vra_bits(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> u32 {
        let ty = |field: &str| {
            node.child_by_field_name(field)
                .map(|n| self.infer_type(&n, source, type_map))
        };
        match node.kind() {
            // A plain binary operation produces a value; what bounds it is
            // where that value is stored, not how wide its operands were
            // declared.
            "binary_expression" => self.result_width_bits(node, source, type_map),
            // A compound assignment or an update/unary operation writes back
            // into its own target, so the target *is* the destination.
            _ => match (ty("left"), ty("argument")) {
                (Some(l), _) => Self::stored_type_bits(&l),
                (None, Some(a)) => Self::stored_type_bits(&a),
                (None, None) => PROMOTED_ARITH_BITS,
            },
        }
    }

    /// When no cross-file context is present (`function_summaries` empty — e.g.
    /// unit tests or a single-file run) the taint channels are a no-op; the
    /// value-based VRA-overflow channel still applies, and otherwise the gate
    /// returns true, preserving the rule's legacy behavior and existing test
    /// expectations.
    fn has_risky_operand_provenance(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        // VRA-concrete-overflow channel: a provably-overflowing expression
        // (e.g. INT_MAX + 1, width-sensitive for short/char) is risky regardless
        // of operand provenance. Value-based, so it works without cross-file
        // context too.
        let vra_bits = self.operand_vra_bits(node, source, type_map);
        if const_eval::expression_overflows_signed_vra(
            node,
            source,
            &self.current_macros.borrow(),
            vra_bits,
            self.value_ranges_at(node, source, type_map).as_ref(),
        ) {
            return true;
        }

        let summaries = self.function_summaries.borrow();
        if summaries.is_empty() {
            return true;
        }
        let func = match ast_utils::find_containing_function(node) {
            Some(f) => f,
            None => return true,
        };
        let body = match func.child_by_field_name("body") {
            Some(b) => b,
            None => return true,
        };

        // Compute (once per function) the set of variable names fed from a risky
        // source, memoized by the function node id.
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
            int_provenance::operand_is_risky(op, risky_vars, &summaries, &global_writers, source)
        })
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
        summaries: &HashMap<String, FunctionSummary>,
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
        // identifier initialized from a call_expression. Returns None if
        // the node is not call-derived.
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

        // Check if either operand is opaque + small literal
        let callee = if is_small_literal(&right) {
            resolve_callee(&left)
        } else if is_small_literal(&left) {
            resolve_callee(&right)
        } else {
            return false; // Neither side is a small literal
        };

        let callee = match callee {
            Some(name) => name,
            None => return false, // Not call-derived, not opaque
        };

        // Known full-range functions: never suppress (atoi, rand, strtol, etc.)
        if std_functions::is_full_range_return_function(&callee) {
            return false;
        }

        // Local function carrying taint (directly or transitively) returns
        // untrusted values; or one with a proven wide return range: don't
        // suppress. Keeps the small-increment heuristic consistent with the
        // provenance gate for cross-function tainted-return data flow.
        if let Some(summary) = summaries.get(&callee) {
            if summary.has_env03_taint_source || summary.returns_tainted {
                return false;
            }
            if let Some(ref return_range) = summary.return_range {
                let signed_danger = i32::MAX as i64 - 10;
                if return_range.max >= signed_danger {
                    return false;
                }
            }
        }

        // Default: suppress (safe for strlen, wcslen, unknown helpers)
        true
    }

    fn contains_arithmetic(&self, expr: &str) -> bool {
        expr.contains('+') || expr.contains('-') || expr.contains('*') || expr.contains('/')
    }

    fn is_constant_expression(&self, expr: &str) -> bool {
        // Check if expression is a constant (literal number or named constant like INT_MAX)
        let trimmed = expr.trim();

        // Numeric literals
        if trimmed
            .chars()
            .all(|c| c.is_ascii_digit() || c == '-' || c == '+')
        {
            return true;
        }

        // Named constants
        if trimmed.contains("INT_MAX")
            || trimmed.contains("INT_MIN")
            || trimmed.contains("LONG_MAX")
            || trimmed.contains("LONG_MIN")
            || trimmed.contains("LLONG_MAX")
            || trimmed.contains("LLONG_MIN")
            || trimmed.contains("UINT_MAX")
            || trimmed.contains("SIZE_MAX")
        {
            return true;
        }

        false
    }

    /// Check if a binary expression is inside a for-loop with a small constant bound,
    /// making overflow impossible (e.g., `i * i` where `i < 100`).
    ///
    /// Requires the operation's operands to actually include the loop
    /// variable — a small loop trip count says nothing about the range of
    /// an unrelated value used inside the loop body (e.g. `data * 2` where
    /// `data` comes from external input, inside `for (j = 0; j < 1; j++)`).
    /// Pre-existing gap found while auditing task 302's comment-sanitization
    /// fix here: 18 genuine Juliet overflow/underflow violations (flow
    /// variant 17, for-loop control flow) were only being correctly flagged
    /// because a comment mentioning "LLONG_MAX" (substring-matching
    /// "LONG_MAX") coincidentally tripped the near-limit-value early-return
    /// below on the unsanitized text — not because the heuristic itself
    /// checked operand relevance.
    fn is_in_bounded_for_loop(&self, node: &Node, source: &str) -> bool {
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "for_statement" {
                // Sanitized so a comment/string literal anywhere in the loop
                // (including its body) can't spoof a limit macro and flip
                // this bounded-loop determination.
                let for_text = get_sanitized_node_text(&parent, source);
                // Check that the loop doesn't involve near-limit values
                if for_text.contains("INT_MAX")
                    || for_text.contains("LONG_MAX")
                    || for_text.contains("INT_MIN")
                    || for_text.contains("LONG_MIN")
                {
                    return false;
                }
                // Heuristic: if the for-loop condition contains a small numeric bound
                // (< 4 digits), the loop variable won't overflow in typical arithmetic
                // — but only when the flagged operation actually operates on that
                // loop variable (not an unrelated value merely used inside the loop).
                if let Some(condition) = parent.child_by_field_name("condition") {
                    let cond_text = get_node_text(&condition, source);
                    // Look for patterns like "i < 100" or "i <= 999"
                    let bound_re = cond_text
                        .split(|c: char| !c.is_ascii_digit())
                        .filter(|s| !s.is_empty())
                        .any(|num| {
                            num.len() <= 4
                                && num.parse::<i64>().is_ok_and(|n| (0..=10000).contains(&n))
                        });
                    if bound_re {
                        let loop_vars = self.extract_operand_names(&condition, source);
                        let op_vars = self.extract_operand_names(node, source);
                        if op_vars.iter().any(|v| loop_vars.contains(v)) {
                            return true;
                        }
                    }
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

    fn is_in_safe_for_loop(&self, node: &Node, source: &str) -> bool {
        // Walk up the tree to see if this node is in a for_statement
        // Only consider it safe if the loop has clear small bounds
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "for_statement" {
                // Check if this is a typical safe for loop (starting from 0 or small value)
                // by looking at the initializer
                if let Some(initializer) = parent.child_by_field_name("initializer") {
                    // Convert initializer to text and check if it's safe
                    // Safe patterns: i = 0, i = 1, etc. (small constants)
                    // Unsafe patterns: i = INT_MAX - 2, etc.
                    let init_text = get_node_text(&initializer, source);
                    if init_text.contains("INT_MAX")
                        || init_text.contains("LONG_MAX")
                        || init_text.contains("INT_MIN")
                        || init_text.contains("LONG_MIN")
                    {
                        return false; // Unsafe - loop starts near limits
                    }
                    return true; // Safe - typical for loop
                }
            }
            // Stop at function boundary
            if parent.kind() == "function_definition" {
                break;
            }
            current = parent.parent();
        }
        false
    }

    fn has_overflow_check_addition(&self, node: &Node, source: &str) -> bool {
        // First check the immediate surrounding context (parent/grandparent) — strict pattern
        if self.has_surrounding_check(node, source, &["INT_MAX", "INT_MIN", " - ", " > ", " < "]) {
            return true;
        }

        // Check for any signed limit macro with a comparison operator in the function.
        // Relaxed from requiring ALL of [INT_MAX, INT_MIN, " - ", " > ", " < "] to
        // requiring any limit macro + comparison — handles CHAR_MAX, SHRT_MAX, etc.
        // The scoped check (guard_keywords + operand match) ensures precision.
        self.has_function_level_overflow_check(node, source, &[" > "])
            || self.has_function_level_overflow_check(node, source, &[" < "])
            || self.has_function_level_overflow_check(node, source, &[" >= "])
            || self.has_function_level_overflow_check(node, source, &[" <= "])
    }

    fn has_overflow_check_subtraction(&self, node: &Node, source: &str) -> bool {
        // First check the immediate surrounding context (parent/grandparent)
        if self.has_surrounding_check(node, source, &["INT_MAX", "INT_MIN", " + ", " > ", " < "]) {
            return true;
        }

        // Then check the broader function context for overflow checks
        self.has_function_level_overflow_check(
            node,
            source,
            &["INT_MAX", "INT_MIN", " + ", " > ", " < "],
        )
    }

    fn has_overflow_check_multiplication(&self, node: &Node, source: &str) -> bool {
        // Check for multiplication overflow patterns:
        // 1. if (a > INT_MAX / b) - division-based check
        // 2. Complex checks with INT_MAX/INT_MIN and division
        if self.has_surrounding_check(node, source, &["INT_MAX", " / "])
            || self.has_surrounding_check(node, source, &["INT_MIN", " / "])
            || self.has_surrounding_check(node, source, &["LONG_MAX", " / "])
            || self.has_surrounding_check(node, source, &["LONG_MIN", " / "])
        {
            return true;
        }

        // Function-level checks
        if self.has_function_level_patterns_any(node, source, &["INT_MAX", " / "])
            || self.has_function_level_patterns_any(node, source, &["INT_MIN", " / "])
            || self.has_function_level_patterns_any(node, source, &["LONG_MAX", " / "])
            || self.has_function_level_patterns_any(node, source, &["LONG_MIN", " / "])
        {
            return true;
        }

        false
    }

    fn has_division_overflow_check(&self, node: &Node, source: &str) -> bool {
        // Check for INT_MIN/-1 or LONG_MIN/-1 or LLONG_MIN/-1 division overflow checks
        if self.has_surrounding_check(node, source, &["INT_MIN", " == ", " -1"])
            || self.has_surrounding_check(node, source, &["LONG_MIN", " == ", " -1"])
            || self.has_surrounding_check(node, source, &["LLONG_MIN", " == ", " -1"])
        {
            return true;
        }

        self.has_function_level_patterns_any(node, source, &["INT_MIN", " == ", " -1"])
            || self.has_function_level_patterns_any(node, source, &["LONG_MIN", " == ", " -1"])
            || self.has_function_level_patterns_any(node, source, &["LLONG_MIN", " == ", " -1"])
    }

    fn has_modulo_overflow_check(&self, node: &Node, source: &str) -> bool {
        // Check for INT_MIN%- 1 or LONG_MIN%-1 or LLONG_MIN%-1 modulo overflow checks
        if self.has_surrounding_check(node, source, &["INT_MIN", " == ", " -1"])
            || self.has_surrounding_check(node, source, &["LONG_MIN", " == ", " -1"])
            || self.has_surrounding_check(node, source, &["LLONG_MIN", " == ", " -1"])
        {
            return true;
        }

        self.has_function_level_patterns_any(node, source, &["INT_MIN", " == ", " -1"])
            || self.has_function_level_patterns_any(node, source, &["LONG_MIN", " == ", " -1"])
            || self.has_function_level_patterns_any(node, source, &["LLONG_MIN", " == ", " -1"])
    }

    fn has_negation_overflow_check(&self, node: &Node, source: &str) -> bool {
        // Check for negation of INT_MIN, LONG_MIN, or LLONG_MIN
        if self.has_surrounding_check(node, source, &["INT_MIN", " == "])
            || self.has_surrounding_check(node, source, &["LONG_MIN", " == "])
            || self.has_surrounding_check(node, source, &["LLONG_MIN", " == "])
        {
            return true;
        }

        self.has_function_level_patterns_any(node, source, &["INT_MIN", " == "])
            || self.has_function_level_patterns_any(node, source, &["LONG_MIN", " == "])
            || self.has_function_level_patterns_any(node, source, &["LLONG_MIN", " == "])
    }

    fn has_shift_overflow_check(&self, node: &Node, source: &str) -> bool {
        // Check for left shift overflow patterns:
        // Complete check requires BOTH:
        // 1. Shift amount validation AND value range check
        // 2. Value range check: a > (INT_MAX >> b) or similar with LONG_MAX

        // Check for value range pattern (most comprehensive)
        if self.has_surrounding_check(node, source, &["LONG_MAX", " >> "])
            || self.has_surrounding_check(node, source, &["INT_MAX", " >> "])
        {
            return true;
        }

        if self.has_function_level_patterns_any(node, source, &["LONG_MAX", " >> "])
            || self.has_function_level_patterns_any(node, source, &["INT_MAX", " >> "])
        {
            return true;
        }

        // Only accept PRECISION if it's combined with value range checks
        // (PRECISION alone is insufficient - see wiki_noncompliant_6)
        if (self.has_surrounding_check(node, source, &["PRECISION"])
            || self.has_function_level_patterns_any(node, source, &["PRECISION"]))
            && (self.has_function_level_patterns_any(node, source, &[" >> "])
                || self.has_function_level_patterns_any(node, source, &[" < ", "sizeof"]))
        {
            return false; // PRECISION + shift amount check only is insufficient
        }

        // sizeof-based complete checks
        self.has_surrounding_check(node, source, &[" < ", "sizeof", "* 8"])
    }

    fn has_overflow_check_compound(&self, node: &Node, source: &str) -> bool {
        if self.has_surrounding_check(node, source, &["if", "INT_MAX", "INT_MIN"]) {
            return true;
        }
        self.has_function_level_overflow_check(node, source, &["if", "INT_MAX", "INT_MIN"])
    }

    fn has_overflow_check_update(&self, node: &Node, source: &str) -> bool {
        // For increment: check if value == INT_MAX
        // For decrement: check if value == INT_MIN
        // We need to detect EITHER check, not both
        if self.has_surrounding_check(node, source, &["if", "INT_MAX", " == "])
            || self.has_surrounding_check(node, source, &["if", "INT_MIN", " == "])
        {
            return true;
        }

        self.has_function_level_patterns_any(node, source, &["if", "INT_MAX", " == "])
            || self.has_function_level_patterns_any(node, source, &["if", "INT_MIN", " == "])
    }

    fn has_allocation_overflow_check(&self, node: &Node, source: &str) -> bool {
        self.has_surrounding_check(node, source, &["SIZE_MAX", " / ", " > ", "if"])
    }

    fn has_memory_function_overflow_check(&self, node: &Node, source: &str) -> bool {
        self.has_surrounding_check(node, source, &["SIZE_MAX", " > ", "if"])
    }

    fn has_abs_overflow_check(&self, node: &Node, source: &str) -> bool {
        // Check if there's a check for INT_MIN/LONG_MIN/LLONG_MIN before the abs call
        if self.has_surrounding_check(node, source, &["INT_MIN", "if"])
            || self.has_surrounding_check(node, source, &["LONG_MIN", "if"])
            || self.has_surrounding_check(node, source, &["LLONG_MIN", "if"])
        {
            return true;
        }
        self.has_function_level_overflow_check(node, source, &["INT_MIN", "if"])
            || self.has_function_level_overflow_check(node, source, &["LONG_MIN", "if"])
            || self.has_function_level_overflow_check(node, source, &["LLONG_MIN", "if"])
    }

    /// Check if a binary operation is part of a comparison expression (used in overflow checking)
    fn is_part_of_comparison(&self, node: &Node, source: &str) -> bool {
        let mut current = node.parent();

        while let Some(parent) = current {
            // If we find a binary_expression parent, check if it's a comparison operator
            if parent.kind() == "binary_expression" {
                // Get the operator
                for i in 0..parent.child_count() {
                    if let Some(child) = parent.child(i) {
                        let text = get_node_text(&child, source);
                        // Check if this is a comparison operator
                        if matches!(text, ">" | "<" | ">=" | "<=" | "==" | "!=") {
                            return true;
                        }
                    }
                }
            }

            // Stop at statement boundaries to avoid going too far up the tree
            if matches!(
                parent.kind(),
                "expression_statement"
                    | "return_statement"
                    | "declaration"
                    | "function_definition"
                    | "compound_statement"
            ) {
                break;
            }

            current = parent.parent();
        }

        false
    }

    /// Check if the function containing this node has overflow checking code (all patterns must match).
    /// Scoped to operands: requires at least one operand name from the flagged expression to appear
    /// near the overflow guard pattern, preventing one variable's check from suppressing another's.
    fn has_function_level_overflow_check(
        &self,
        node: &Node,
        source: &str,
        patterns: &[&str],
    ) -> bool {
        let operand_names = self.extract_operand_names(node, source);
        self.has_function_level_overflow_check_scoped(node, source, patterns, &operand_names)
    }

    /// Check if the function containing this node has overflow checking code (all patterns must match).
    /// Variant used when operand names are not applicable (e.g., compound assignments).
    fn has_function_level_patterns_any(
        &self,
        node: &Node,
        source: &str,
        patterns: &[&str],
    ) -> bool {
        let operand_names = self.extract_operand_names(node, source);
        self.has_function_level_overflow_check_scoped(node, source, patterns, &operand_names)
    }

    /// Core operand-scoped function-level overflow check.
    /// Checks that:
    /// 1. All the given patterns exist in the function (e.g., "INT_MAX", " - ")
    /// 2. At least one operand from the flagged expression appears in a line that
    ///    also contains at least one of the overflow-guard keywords (INT_MAX, INT_MIN, etc.)
    fn has_function_level_overflow_check_scoped(
        &self,
        node: &Node,
        source: &str,
        patterns: &[&str],
        operand_names: &[String],
    ) -> bool {
        // Find the containing function
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "function_definition" {
                // Sanitized so a comment/string literal elsewhere in the
                // function can't spoof an overflow-guard pattern and
                // silently suppress a real violation. Memoized per function
                // (task 672): this used to re-walk the whole function body
                // for every risky-operand candidate.
                let func_text = {
                    let mut cache = self.function_text_cache.borrow_mut();
                    cache
                        .entry(parent.id())
                        .or_insert_with(|| get_sanitized_node_text(&parent, source).into())
                        .clone()
                };

                // First: do the patterns even exist in this function?
                if !patterns.iter().all(|p| func_text.contains(p)) {
                    return false;
                }

                // If we have no operand names to scope against, fall back to
                // the old behavior (patterns found anywhere in the function)
                if operand_names.is_empty() {
                    return true;
                }

                // The overflow-guard keywords we look for near operand names
                let guard_keywords = [
                    "INT_MAX",
                    "INT_MIN",
                    "LONG_MAX",
                    "LONG_MIN",
                    "LLONG_MAX",
                    "LLONG_MIN",
                    "UINT_MAX",
                    "SIZE_MAX",
                    "CHAR_MAX",
                    "CHAR_MIN",
                    "SCHAR_MAX",
                    "SCHAR_MIN",
                    "SHRT_MAX",
                    "SHRT_MIN",
                ];

                // Search for lines that contain an overflow guard keyword AND
                // at least one operand name from the flagged expression.
                for line in func_text.lines() {
                    let trimmed = line.trim();
                    let has_guard = guard_keywords.iter().any(|kw| trimmed.contains(kw));
                    if !has_guard {
                        continue;
                    }
                    if operand_names
                        .iter()
                        .any(|name| self.contains_word(trimmed, name))
                    {
                        return true;
                    }
                }

                return false;
            }
            current = parent.parent();
        }
        false
    }

    /// Check if `text` contains `word` as a whole word (not a substring of another identifier).
    fn contains_word(&self, text: &str, word: &str) -> bool {
        overflow_helpers::contains_word(text, word)
    }

    /// Check if the arithmetic node is inside a block guarded by a type-limit bounds check.
    /// Walks up ancestors (up to 15 levels) looking for an `if_statement` whose condition
    /// references a signed type-limit macro AND at least one operand of the arithmetic.
    fn is_inside_bounds_checked_block(
        &self,
        node: &Node,
        source: &str,
        op_names: &[String],
    ) -> bool {
        const SIGNED_LIMIT_MACROS: &[&str] = &[
            "INT_MAX",
            "INT_MIN",
            "LONG_MAX",
            "LONG_MIN",
            "LLONG_MAX",
            "LLONG_MIN",
            "CHAR_MAX",
            "CHAR_MIN",
            "SCHAR_MAX",
            "SCHAR_MIN",
            "SHRT_MAX",
            "SHRT_MIN",
        ];

        let mut current = *node;
        let mut depth = 0;
        while let Some(parent) = current.parent() {
            depth += 1;
            if depth > 15 {
                break;
            }
            if parent.kind() == "function_definition" {
                break;
            }
            if matches!(
                parent.kind(),
                "if_statement" | "while_statement" | "for_statement"
            ) {
                if let Some(condition) = parent.child_by_field_name("condition") {
                    let cond_text = get_node_text(&condition, source);
                    let has_limit = SIGNED_LIMIT_MACROS
                        .iter()
                        .any(|m| self.contains_word(cond_text, m));
                    if has_limit {
                        if op_names.is_empty() {
                            return true;
                        }
                        if op_names
                            .iter()
                            .any(|name| self.contains_word(cond_text, name))
                        {
                            return true;
                        }
                    }
                    // For while/for: check if the loop-bounded variable is the
                    // same as the operation's target variable. E.g., `while (attempts < MAX)`
                    // bounds `attempts`, so `attempts++` is safe, but `sum += x` is not.
                    if matches!(parent.kind(), "while_statement" | "for_statement") {
                        let bounded_vars = self.extract_loop_bounded_vars(&condition, source);
                        if let Some(target) = self.extract_mutation_target(node, source) {
                            if bounded_vars.contains(&target) {
                                return true;
                            }
                        }
                    }
                }
            }
            current = parent;
        }
        false
    }

    /// Extract the target variable of a mutation operation.
    /// For `x += y` → "x", for `x++` → "x", for `a * b` → None (not a mutation).
    fn extract_mutation_target(&self, node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "augmented_assignment_expression" | "assignment_expression" => {
                if let Some(left) = node.child_by_field_name("left") {
                    if left.kind() == "identifier" {
                        let name = get_node_text(&left, source);
                        if !name.is_empty() {
                            return Some(name.to_string());
                        }
                    }
                }
                None
            }
            "update_expression" => {
                if let Some(arg) = node.child_by_field_name("argument") {
                    if arg.kind() == "identifier" {
                        let name = get_node_text(&arg, source);
                        if !name.is_empty() {
                            return Some(name.to_string());
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Extract variable names that are bounded by comparison operators in a
    /// loop condition. E.g., `i < N` → ["i"], `attempts < MAX && ret != 0` → ["attempts"].
    fn extract_loop_bounded_vars(&self, condition: &Node, source: &str) -> Vec<String> {
        let cond_text = get_node_text(condition, source);
        // Strip outer parens
        let cond_text = cond_text
            .strip_prefix('(')
            .and_then(|s| s.strip_suffix(')'))
            .unwrap_or(cond_text);
        let mut vars = Vec::new();
        // Split on && to handle compound conditions
        for part in cond_text.split("&&") {
            let part = part.trim();
            // Look for `var < expr`, `var <= expr`, `var > expr`, `var >= expr`
            for op in &["<=", ">=", "<", ">"] {
                if let Some(pos) = part.find(op) {
                    let left = part[..pos].trim();
                    let right = part[pos + op.len()..].trim();
                    // Left-side bounded: `var < BOUND`
                    if matches!(*op, "<" | "<=") && is_simple_c_identifier(left) {
                        vars.push(left.to_string());
                    }
                    // Right-side bounded: `BOUND > var`
                    if matches!(*op, ">" | ">=") && is_simple_c_identifier(right) {
                        vars.push(right.to_string());
                    }
                    break; // Only match first operator per sub-expression
                }
            }
        }
        vars
    }

    fn has_surrounding_check(&self, node: &Node, source: &str, patterns: &[&str]) -> bool {
        if let Some(parent) = node.parent() {
            if let Some(grandparent) = parent.parent() {
                // Sanitized so a comment/string literal in the surrounding
                // context can't spoof an overflow-guard pattern and
                // silently suppress a real violation.
                let context = get_sanitized_node_text(&grandparent, source);
                return patterns.iter().all(|pattern| context.contains(pattern));
            }
        }
        false
    }

    fn get_operator(&self, node: &Node, source: &str) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let text = get_node_text(&child, source);
                if matches!(text, "+" | "-" | "*" | "/" | "%" | "<<" | ">>") {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    fn get_assignment_operator(&self, node: &Node, source: &str) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let text = get_node_text(&child, source);
                if matches!(text, "+=" | "-=" | "*=" | "/=" | "%=" | "<<=" | ">>=") {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    fn get_unary_operator(&self, node: &Node, source: &str) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let text = get_node_text(&child, source);
                if matches!(text, "-" | "+" | "!" | "~") {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    fn get_update_operator(&self, node: &Node, source: &str) -> String {
        overflow_helpers::get_update_operator(node, source)
    }
}

fn is_simple_c_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_alphanumeric() || c == '_')
}
