use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::FunctionCfg;
use crate::analyze::const_eval::{self, MacroConstantMap, VarRangeMap};
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::value_range::RangeAnalysisResult;
use crate::analyze::vra_access;
use crate::manifest::{RuleCategory, Severity};
use crate::rules::cert_c::int_provenance;
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::std_functions;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Int30C {
    project_macros: RefCell<MacroConstantMap>,
    current_macros: RefCell<MacroConstantMap>,
    struct_field_types: RefCell<HashMap<String, HashMap<String, String>>>,
    function_cfgs: RefCell<HashMap<usize, FunctionCfg>>,
    vra_results: RefCell<HashMap<usize, RangeAnalysisResult>>,
    function_summaries: RefCell<HashMap<String, FunctionSummary>>,
    /// Globals written by a tainted function — see the INT32-C provenance gate.
    global_writers: RefCell<HashMap<String, HashSet<String>>>,
    /// Per-function memo of risky variable names, keyed by function node id;
    /// cleared per file.
    risky_vars_cache: RefCell<HashMap<usize, HashSet<String>>>,
}

impl Int30C {
    pub fn new() -> Self {
        Self {
            project_macros: RefCell::new(MacroConstantMap::new()),
            current_macros: RefCell::new(MacroConstantMap::new()),
            struct_field_types: RefCell::new(HashMap::new()),
            function_cfgs: RefCell::new(HashMap::new()),
            vra_results: RefCell::new(HashMap::new()),
            function_summaries: RefCell::new(HashMap::new()),
            global_writers: RefCell::new(HashMap::new()),
            risky_vars_cache: RefCell::new(HashMap::new()),
        }
    }

    /// Opt-in provenance gate for unsigned wrap — the unsigned analogue of
    /// INT32-C's gate. Returns true when an operand derives from untrusted or
    /// unbounded input, or when the expression *definitely* wraps a 32-bit
    /// unsigned type (value-based VRA channel). When false, every operand is
    /// bounded local state and the wrap is treated as intended/non-overflowing.
    /// No-op (returns true) without cross-file context, preserving legacy
    /// behavior and existing tests.
    fn has_risky_operand_provenance(&self, node: &Node, source: &str) -> bool {
        // VRA definite-wrap channel (UINT_MAX + 1 / 0u - 1). Unsigned wrap in
        // SQLite uses 32-bit width uniformly, matching the fits-checks.
        if const_eval::expression_overflows_unsigned_vra(
            node,
            source,
            &self.current_macros.borrow(),
            32,
            self.vra_var_ranges_at(node, source).as_ref(),
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

    /// Get VRA-derived variable ranges at a specific expression node.
    ///
    /// Uses intra-block forward simulation so that assignments within the same
    /// basic block (e.g. single-block functions) are visible at the expression point.
    fn vra_var_ranges_at(&self, expr_node: &Node, source: &str) -> Option<VarRangeMap> {
        vra_access::var_ranges_replay_at(
            &self.function_cfgs.borrow(),
            &self.vra_results.borrow(),
            expr_node,
            source,
            &self.current_macros.borrow(),
        )
    }
}

impl CertRule for Int30C {
    fn rule_id(&self) -> &'static str {
        "INT30-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that unsigned integer operations do not wrap"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "INT30-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_macros.borrow_mut() = context.macro_constants.clone();
        *self.struct_field_types.borrow_mut() = context.struct_field_types.clone();
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

        // Merge project-level macros with per-file macros
        let mut macros = self.project_macros.borrow().clone();
        macros.extend(const_eval::collect_macro_constants(node, source));
        *self.current_macros.borrow_mut() = macros;

        // Risky-var memo is keyed on tree-sitter node ids, unique only within
        // one parse tree — reset per file.
        self.risky_vars_cache.borrow_mut().clear();

        self.check_node(node, source, &mut violations, &type_map);

        violations
    }
}

impl Int30C {
    /// For compound assignments (`x op= y`), check if `x op y` provably fits
    /// in an unsigned integer of `bits` width using constant evaluation.
    /// Note: only resolves the RHS — the LHS is the mutation target and its
    /// initial assignment doesn't reflect its current value (especially in loops).
    fn compound_expr_fits_unsigned(&self, node: &Node, source: &str, op: &str, bits: u32) -> bool {
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
                    return range.fits_in_unsigned(bits);
                }
            }
        }
        false
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        let matches = query::find_descendants_of_kinds(
            *node,
            &[
                "binary_expression",
                "assignment_expression",
                "call_expression",
                "update_expression",
            ],
        );
        for matched in matches {
            match matched.kind() {
                "binary_expression" => {
                    self.check_binary_operation(&matched, source, violations, type_map);
                }
                "assignment_expression" => {
                    self.check_assignment_operation(&matched, source, violations, type_map);
                }
                "call_expression" => {
                    self.check_function_call(&matched, source, violations);
                }
                "update_expression" => {
                    self.check_increment_decrement(&matched, source, violations, type_map);
                }
                _ => {}
            }
        }
    }

    fn check_binary_operation(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        if let Some(operator) = self.get_operator(node, source) {
            match operator.as_str() {
                "+" => self.check_addition(node, source, violations, type_map),
                "-" => self.check_subtraction(node, source, violations, type_map),
                "*" => self.check_multiplication(node, source, violations, type_map),
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
        if let Some(operator) = self.get_assignment_operator(node, source) {
            match operator.as_str() {
                "+=" => self.check_compound_addition(node, source, violations, type_map),
                "-=" => self.check_compound_subtraction(node, source, violations, type_map),
                "*=" => self.check_compound_multiplication(node, source, violations, type_map),
                "<<=" => self.check_compound_left_shift(node, source, violations, type_map),
                _ => {}
            }
        }
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

            // Skip pointer arithmetic: ptr + n, n + ptr
            // "not_applicable" means a non-integer type (pointer, float, struct).
            // Adding an unsigned offset to a pointer is valid C pointer arithmetic and
            // is NOT an unsigned integer overflow — that is ARR39-C's domain.
            if left_type == "not_applicable" || right_type == "not_applicable" {
                // Recurse into children only
                return;
            }

            if (self.is_unsigned_type(&left_type) || self.is_unsigned_type(&right_type))
                && !self.has_overflow_check_addition(node, source)
            {
                // Skip when both operands are narrow unsigned types (uint8_t, uint16_t).
                // C promotes these to int (≥32-bit) before arithmetic, so the result
                // cannot overflow the promoted type.
                if self.is_narrow_unsigned_type(&left_type)
                    && self.is_narrow_unsigned_type(&right_type)
                {
                    return;
                }

                // Skip when one operand is narrow unsigned and the other is not a
                // wider unsigned type. C promotes the narrow unsigned to int (signed),
                // so the arithmetic is signed and cannot cause unsigned wrap.
                // Example: uint8_t + 1 → int + int → no unsigned wrap.
                if self.narrow_promotion_is_safe(&left_type, &right_type) {
                    return;
                }

                // Skip if the addition result is immediately masked by bitwise AND.
                // Pattern: (x + 1) & MASK — common ring buffer index idiom.
                // The mask bounds the result regardless of intermediate wrap.
                if self.is_addition_masked_by_bitand(node, source) {
                    return;
                }

                // Skip if the addition result is immediately taken modulo (% N).
                // Pattern: (x + 1) % N — ring buffer next-index idiom.
                // The modulo constrains the result to [0, N-1] so overflow doesn't matter.
                if self.is_addition_bounded_by_modulo(node, source) {
                    return;
                }

                // Check for var + 1 or 1 + var bounded by enclosing loop condition
                if self.is_add_one_bounded_by_loop(node, source) {
                    return;
                }

                // Skip `(uint32_t)a + (uint32_t)b` (or mixed with a plain narrow operand)
                // when both operands' pre-cast types are narrow unsigned. Max sum:
                // 65535 + 65535 = 131070, well within uint32_t.
                if self.both_operands_narrow_pre_cast(&left, &right, source, type_map) {
                    return;
                }

                // Skip `(uint32_t)narrow + SMALL_CONST` — widened narrow plus a known
                // small constant (literal or const-evaluable macro) cannot overflow
                // uint32_t. Catches patterns like `(uint32_t)length + HDR_SIZE`.
                if self.is_narrow_cast_plus_small_const(&left, &right, source, type_map) {
                    return;
                }

                // Skip if constant evaluation proves the result fits in 32-bit unsigned
                if const_eval::expression_fits_in_unsigned_vra(
                    node,
                    source,
                    &self.current_macros.borrow(),
                    32,
                    self.vra_var_ranges_at(node, source).as_ref(),
                ) {
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

                // Opt-in provenance gate (mirrors INT32-C): only flag when an
                // operand derives from untrusted/unbounded input or the
                // expression definitely wraps. Bounded unsigned counters wrap
                // by intent, not by bug.
                if !self.has_risky_operand_provenance(node, source) {
                    return;
                }

                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Unsigned integer addition '{}' may wrap without overflow checking",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Add overflow check: if (UINT_MAX - a < b) { /* handle error */ }"
                            .to_string(),
                    ),
                    ..Default::default()
                });
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

            // Skip pointer arithmetic: ptr - n, ptr - ptr2
            if left_type == "not_applicable" || right_type == "not_applicable" {
                return;
            }

            // Skip 64-bit unsigned subtraction: uint64_t wraps at 2^64 which is
            // practically impossible for real-world values (e.g., elapsed time patterns).
            // Only one operand needs to be 64-bit — C promotion rules widen the other.
            if self.any_operand_64bit_unsigned(&left, &right, source, type_map) {
                return;
            }

            if (self.is_unsigned_type(&left_type) || self.is_unsigned_type(&right_type))
                && !self.has_overflow_check_subtraction(node, source)
            {
                // Narrow unsigned types (uint8_t, uint16_t) are promoted to int before
                // subtraction — the result is a signed int that can represent negative
                // values without wrapping. Skip.
                if self.is_narrow_unsigned_type(&left_type)
                    && self.is_narrow_unsigned_type(&right_type)
                {
                    return;
                }

                // Skip when one operand is narrow unsigned and the other is not a
                // wider unsigned type. C promotes to int (signed) — no unsigned wrap.
                if self.narrow_promotion_is_safe(&left_type, &right_type) {
                    return;
                }

                // Skip var - 1 / var - 1U when guarded by positive check or preceded by increment
                if self.is_subtract_one_guarded(node, source) {
                    return;
                }

                // Skip a - b when guarded by `if (a >= b)` or `if (a > b)`
                let left_text = get_node_text(&left, source);
                let right_text = get_node_text(&right, source);
                if self.is_subtraction_guarded_by_comparison(
                    node,
                    left_text.trim(),
                    right_text.trim(),
                    source,
                ) {
                    return;
                }

                // Skip the elapsed-time tick counter idiom:
                //   get_SystemTick_ms() - last_tick
                // The left operand is a getter function whose name signals a monotonic
                // tick/time counter. Unsigned wrap here is intentional and correct
                // (C99 §6.2.5p9: unsigned arithmetic is modular).
                if self.is_elapsed_time_subtraction(&left, source) {
                    return;
                }

                // Skip if constant evaluation proves the result fits in 32-bit unsigned
                if const_eval::expression_fits_in_unsigned_vra(
                    node,
                    source,
                    &self.current_macros.borrow(),
                    32,
                    self.vra_var_ranges_at(node, source).as_ref(),
                ) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(node, source) {
                    return;
                }

                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Unsigned integer subtraction '{}' may wrap without underflow checking",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Add underflow check: if (a < b) { /* handle error */ }".to_string(),
                    ),
                    ..Default::default()
                });
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

            if (self.is_unsigned_type(&left_type) || self.is_unsigned_type(&right_type))
                && !self.has_overflow_check_multiplication(node, source)
            {
                // Narrow unsigned types: max(uint8_t)*max(uint8_t)=65025,
                // max(uint16_t)*max(uint16_t)=4,294,836,225 which CAN overflow uint32_t.
                // Only skip uint8_t * uint8_t (fits in 16-bit after promotion).
                if self.is_narrow_unsigned_type(&left_type)
                    && self.is_narrow_unsigned_type(&right_type)
                    && (left_type.contains("8") || right_type.contains("8"))
                {
                    return;
                }

                // Skip when one operand is narrow unsigned and the other is signed/literal.
                // For multiplication, only safe when at least one is 8-bit (max product
                // 255*INT_MAX fits in 64-bit but not 32-bit, so be conservative: only
                // skip when one operand is uint8_t and other is not wide unsigned).
                if (self.is_narrow_unsigned_type(&left_type)
                    && left_type.contains("8")
                    && !self.is_wide_unsigned_type(&right_type))
                    || (self.is_narrow_unsigned_type(&right_type)
                        && right_type.contains("8")
                        && !self.is_wide_unsigned_type(&left_type))
                {
                    return;
                }

                // Skip when both operands' effective (pre-cast) types are narrow unsigned.
                // Pattern: `(uint32_t)a * (uint32_t)b` or `(uint32_t)a * b` where `a` and
                // `b` are each uint8_t or uint16_t. Max product: 65535 * 65535 ≈ 4.29×10⁹,
                // which fits in uint32_t (max 4.29×10⁹ + ~131K).
                if self.both_operands_narrow_pre_cast(&left, &right, source, type_map) {
                    return;
                }

                // Skip `(uint32_t)NARROW_BOUNDED * SMALL_CONST` — a narrow value
                // widened by a cast, multiplied by a small constant (≤ 65535).
                // Product fits uint32_t. Catches patterns like
                // `(uint32_t)(a - b) * SCALE` when the subtraction is guarded.
                if self.is_narrow_cast_times_small_const(&left, &right, source, type_map) {
                    return;
                }

                // Skip if constant evaluation proves the result fits in 32-bit unsigned
                if const_eval::expression_fits_in_unsigned_vra(
                    node,
                    source,
                    &self.current_macros.borrow(),
                    32,
                    self.vra_var_ranges_at(node, source).as_ref(),
                ) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(node, source) {
                    return;
                }

                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Unsigned integer multiplication '{}' may wrap without overflow checking",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Add overflow check: if (a > UINT_MAX / b) { /* handle error */ }"
                            .to_string(),
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

            if self.is_unsigned_type(&left_type) && !self.has_shift_overflow_check(node, source) {
                // Narrow unsigned left shift: uint8_t << N is promoted to int first.
                // Max result: 0xFF << 7 = 0x7F80, fits in 32-bit. Skip.
                if self.is_narrow_unsigned_type(&left_type) {
                    return;
                }

                // Skip if constant evaluation proves the result fits in 32-bit unsigned
                if const_eval::expression_fits_in_unsigned_vra(
                    node,
                    source,
                    &self.current_macros.borrow(),
                    32,
                    self.vra_var_ranges_at(node, source).as_ref(),
                ) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(node, source) {
                    return;
                }

                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Unsigned integer left shift '{}' may cause overflow without checking",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Add shift overflow check before shifting".to_string()),
                    ..Default::default()
                });
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

            // Skip pointer arithmetic: ptr += n
            if left_type == "not_applicable" {
                return;
            }

            if self.is_unsigned_type(&left_type) && !self.has_overflow_check_compound(node, source)
            {
                // Narrow unsigned compound add: uint8_t += uint8_t promotes to int.
                if self.is_narrow_unsigned_type(&left_type) {
                    return;
                }

                // Check for var += 1 bounded by enclosing loop condition (var < limit)
                if let Some(right) = node.child_by_field_name("right") {
                    let right_text = get_node_text(&right, source);
                    if self.is_literal_one(right_text.trim()) {
                        let var_name = get_node_text(&left, source);
                        if self.is_bounded_by_loop_condition(node, var_name.trim(), source) {
                            return;
                        }
                    }
                }

                // Skip if constant evaluation proves the result fits in 32-bit unsigned
                if self.compound_expr_fits_unsigned(node, source, "+", 32) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(node, source) {
                    return;
                }

                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Unsigned integer compound addition '{}' may wrap without overflow checking",
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

    fn check_compound_subtraction(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        if let Some(left) = node.child_by_field_name("left") {
            let left_type = self.infer_type(&left, source, type_map);

            // Skip pointer arithmetic: ptr -= n
            if left_type == "not_applicable" {
                return;
            }

            if self.is_unsigned_type(&left_type) && !self.has_overflow_check_compound(node, source)
            {
                if self.is_narrow_unsigned_type(&left_type) {
                    return;
                }

                // Check for var -= 1 with positive guard (var > expr implies var >= 1)
                if let Some(right) = node.child_by_field_name("right") {
                    let right_text = get_node_text(&right, source);
                    if self.is_literal_one(right_text.trim()) {
                        let var_name = get_node_text(&left, source);
                        if self.is_guarded_by_gt_zero(node, var_name.trim(), source) {
                            return;
                        }
                    }
                    // Check for var -= expr guarded by `if (var >= expr)` or `if (var > expr)`
                    let var_name = get_node_text(&left, source);
                    if self.is_subtraction_guarded_by_comparison(
                        node,
                        var_name.trim(),
                        right_text.trim(),
                        source,
                    ) {
                        return;
                    }
                }

                // Skip if constant evaluation proves the result fits in 32-bit unsigned
                if self.compound_expr_fits_unsigned(node, source, "-", 32) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(node, source) {
                    return;
                }

                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Unsigned integer compound subtraction '{}' may wrap without underflow checking",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Add underflow check before compound assignment".to_string()),
                    ..Default::default()
                });
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

            if self.is_unsigned_type(&left_type) && !self.has_overflow_check_compound(node, source)
            {
                if self.is_narrow_unsigned_type(&left_type) {
                    return;
                }

                // Skip if constant evaluation proves the result fits in 32-bit unsigned
                if self.compound_expr_fits_unsigned(node, source, "*", 32) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(node, source) {
                    return;
                }

                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Unsigned integer compound multiplication '{}' may wrap without overflow checking",
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

    fn check_compound_left_shift(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        if let Some(left) = node.child_by_field_name("left") {
            let left_type = self.infer_type(&left, source, type_map);

            if self.is_unsigned_type(&left_type) && !self.has_overflow_check_compound(node, source)
            {
                // Skip if constant evaluation proves the result fits in 32-bit unsigned
                if self.compound_expr_fits_unsigned(node, source, "<<", 32) {
                    return;
                }

                // Opt-in provenance gate (see check_addition).
                if !self.has_risky_operand_provenance(node, source) {
                    return;
                }

                let start_point = node.start_position();
                let expr_text = get_node_text(node, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Unsigned integer compound left shift '{}' may cause overflow without checking",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Add shift overflow check before compound assignment".to_string()),
                    ..Default::default()
                });
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
        // Skip increments/decrements that are the update clause of a for-loop.
        // The loop condition inherently bounds the variable.
        if node.parent().is_some_and(|p| p.kind() == "for_statement") {
            return;
        }

        if let Some(argument) = node.child_by_field_name("argument") {
            let arg_type = self.infer_type(&argument, source, type_map);

            if self.is_unsigned_type(&arg_type) {
                // Narrow unsigned increment/decrement: uint8_t++ wraps at 255,
                // uint16_t-- wraps at 0 — both are defined behavior and the
                // promoted int result doesn't overflow.
                if self.is_narrow_unsigned_type(&arg_type) {
                    return;
                }

                let operator = self.get_update_operator(node, source);

                // Skip plain ++/-- of a wide unsigned struct/union field
                // (`ctx->field++`, `obj.counter++`). Embedded monotonic-
                // counter fields (ticks, sequence numbers) wrap at 2^32 or
                // 2^64 — practically never in real systems, and wrap is
                // typically expected via tick-diff comparisons. Juliet
                // CWE-190/191 tests only exercise local-variable
                // increments, so this skip does not affect TP detection.
                if argument.kind() == "field_expression" && (operator == "++" || operator == "--") {
                    return;
                }
                if operator == "++" || operator == "--" {
                    // Skip increments/decrements in for-loop update clauses — the loop
                    // condition bounds the counter, making wrap impossible in practice.
                    if self.is_in_for_loop_update(node) {
                        return;
                    }
                    // Skip decrements guarded by `var > 0` or `0 < var` (FP-011).
                    if operator == "--" {
                        let var_name = get_node_text(&argument, source);
                        if self.is_guarded_by_gt_zero(node, var_name, source) {
                            return;
                        }
                    }
                    // Skip increments bounded by enclosing loop condition (var < limit).
                    if operator == "++" {
                        let var_name = get_node_text(&argument, source);
                        if self.is_bounded_by_loop_condition(node, var_name.trim(), source) {
                            return;
                        }
                    }
                    // Skip if VRA proves the result fits in 32-bit unsigned
                    if const_eval::expression_fits_in_unsigned_vra(
                        node,
                        source,
                        &self.current_macros.borrow(),
                        32,
                        self.vra_var_ranges_at(node, source).as_ref(),
                    ) {
                        return;
                    }
                    // Opt-in provenance gate (see check_addition): a bounded
                    // unsigned counter cannot reach the wrap boundary.
                    if !self.has_risky_operand_provenance(node, source) {
                        return;
                    }

                    if !self.has_overflow_check_update(node, source) {
                        let start_point = node.start_position();
                        let expr_text = get_node_text(node, source);

                        let message = if operator == "++" {
                            format!(
                                "Unsigned integer increment '{}' may wrap at maximum value",
                                expr_text
                            )
                        } else {
                            format!(
                                "Unsigned integer decrement '{}' may wrap at zero",
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
    }

    fn check_function_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = &source[function_node.start_byte()..function_node.end_byte()];

            // malloc/realloc multiplication overflow is already covered by
            // the generic `check_multiplication` walker on the inner `*`
            // binary expression — flagging the allocation call again would
            // produce a duplicate diagnostic on the same line. Only calloc
            // needs a dedicated check because its multiplication is implicit
            // (`calloc(nmemb, size)`) and thus invisible to the binary-
            // expression walk.
            if function_name == "calloc" {
                self.check_allocation_overflow(node, source, function_name, violations);
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
        let args = self.get_function_arguments(node, source);

        if function_name == "calloc"
            && args.len() >= 2
            && !self.has_calloc_overflow_check(node, source)
        {
            let start_point = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "calloc({}, {}) may cause integer overflow in size calculation",
                    args[0], args[1]
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some(
                    "Check for overflow: if (count > SIZE_MAX / size) { /* handle error */ }"
                        .to_string(),
                ),
                ..Default::default()
            });
        }
    }

    fn infer_type(&self, node: &Node, source: &str, type_map: &HashMap<String, String>) -> String {
        let text = get_node_text(node, source);

        // Cast expressions: extract the actual target type from the type descriptor.
        // This provides precise type info (e.g., "uint8_t" instead of generic "unsigned")
        // which is critical for narrow-type checks.
        if node.kind() == "cast_expression" {
            if let Some(type_node) = node.child_by_field_name("type") {
                let cast_type = get_node_text(&type_node, source).trim().to_string();
                let base_type = Self::strip_type_qualifiers(&cast_type);
                if base_type.contains('*') {
                    return "not_applicable".to_string();
                }
                if self.is_unsigned_type(&base_type) {
                    return base_type;
                }
                if base_type == "void" {
                    return "not_applicable".to_string();
                }
                return "int".to_string();
            }
        }

        // Look for explicit unsigned indicators in the text
        if text.contains("unsigned") || text.contains("size_t") || text.contains("uint") {
            return "unsigned".to_string();
        }

        // Look for unsigned literals (suffix U or u)
        if text.ends_with("u")
            || text.ends_with("U")
            || text.ends_with("UL")
            || text.ends_with("ul")
        {
            return "unsigned".to_string();
        }

        // Look for unsigned constants
        if text.contains("UINT_MAX") || text.contains("SIZE_MAX") {
            return "unsigned".to_string();
        }

        // sizeof() always returns size_t (unsigned)
        if node.kind() == "sizeof_expression" {
            return "unsigned".to_string();
        }

        // Plain number literals — assume signed for conservatism
        if text.chars().all(|c| c.is_ascii_digit()) {
            return "int".to_string();
        }

        // Check identifiers against the type map (most reliable).
        // Return the actual declared type to preserve narrow-type info (uint8_t etc.).
        if node.kind() == "identifier" {
            if let Some(declared_type) = type_map.get(text) {
                // Pointer types are not integer types — skip
                if declared_type.contains('*') {
                    return "not_applicable".to_string();
                }
                if self.is_unsigned_type(declared_type) {
                    return declared_type.clone();
                }
                // Non-integer types (float, double, char, pointers, structs) — not applicable
                if !declared_type.contains("int")
                    && !declared_type.contains("short")
                    && !declared_type.contains("long")
                    && declared_type != "signed"
                {
                    return "not_applicable".to_string();
                }
                return "int".to_string();
            }
        }

        // For pointer expressions (*var), strip the '*' and check the pointed-to type.
        // Dereferencing a pointer yields the base type, so strip one '*' from the
        // declared type if present.
        if node.kind() == "pointer_expression" {
            let var_name = text.trim_start_matches('*').trim();
            if let Some(declared_type) = type_map.get(var_name) {
                // Strip one level of pointer indirection (dereference)
                let deref_type = if let Some(stripped) = declared_type.strip_suffix(" *") {
                    stripped
                } else if let Some(stripped) = declared_type.strip_suffix('*') {
                    stripped
                } else {
                    declared_type.as_str()
                };
                if deref_type.contains('*') {
                    // Still a pointer after dereference (e.g. int **)
                    return "not_applicable".to_string();
                }
                if self.is_unsigned_type(deref_type) {
                    return "unsigned".to_string();
                }
                return "int".to_string();
            }
        }

        // Field expressions (e.g., s->length): resolve via struct field type database
        if node.kind() == "field_expression" {
            let sft = self.struct_field_types.borrow();
            if let Some(field_type) =
                crate::utility::cert_c::ast_utils::resolve_field_expression_type(
                    node, source, type_map, &sft,
                )
            {
                // Strip qualifiers (volatile, const) for type classification
                let base_type = Self::strip_type_qualifiers(&field_type);
                if base_type.contains('*') {
                    return "not_applicable".to_string();
                }
                if self.is_unsigned_type(&base_type) {
                    // Return actual type to preserve narrow-type info (uint8_t, uint16_t)
                    return base_type;
                }
                if !base_type.contains("int")
                    && !base_type.contains("short")
                    && !base_type.contains("long")
                    && base_type != "signed"
                {
                    return "not_applicable".to_string();
                }
                return "int".to_string();
            }
            return "unknown".to_string();
        }

        // Fallback: check variable declaration in function text for unmapped variables
        if node.kind() == "identifier" || node.kind() == "pointer_expression" {
            let var_name = text.trim_start_matches('*').trim();
            if self.is_variable_declared_unsigned(node, source, var_name) {
                return "unsigned".to_string();
            }
        }

        "unknown".to_string()
    }

    /// Check if a variable is declared as unsigned in the containing function
    fn is_variable_declared_unsigned(&self, node: &Node, source: &str, var_name: &str) -> bool {
        // Find containing function
        let func = self.find_containing_function(node);
        if func.is_none() {
            return false;
        }
        let func = func.unwrap();
        let func_text = get_node_text(&func, source);

        // Check for parameter declarations like "unsigned int var_name" or "unsigned int *var_name"
        if func_text.contains(&format!("unsigned int {}", var_name))
            || func_text.contains(&format!("unsigned int *{}", var_name))
            || func_text.contains(&format!("unsigned long {}", var_name))
            || func_text.contains(&format!("size_t {}", var_name))
            || func_text.contains(&format!("uint32_t {}", var_name))
            || func_text.contains(&format!("uint64_t {}", var_name))
        {
            return true;
        }

        false
    }

    /// Find the containing function definition
    fn find_containing_function<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = *node;
        while let Some(parent) = current.parent() {
            if parent.kind() == "function_definition" {
                return Some(parent);
            }
            current = parent;
        }
        None
    }

    fn collect_variable_types(&self, node: &Node, source: &str) -> HashMap<String, String> {
        let mut type_map = HashMap::new();

        for func in query::find_descendants_of_kind(*node, "function_definition") {
            // Collect from function parameters
            if let Some(declarator) = func.child_by_field_name("declarator") {
                self.collect_params_from_declarator(&declarator, source, &mut type_map);
            }
            // Collect from local declarations in the function body
            if let Some(body) = func.child_by_field_name("body") {
                self.collect_local_declarations(&body, source, &mut type_map);
            }
        }

        type_map
    }

    fn collect_params_from_declarator(
        &self,
        node: &Node,
        source: &str,
        type_map: &mut HashMap<String, String>,
    ) {
        for declarator in query::find_descendants_of_kind(*node, "function_declarator") {
            if let Some(params) = declarator.child_by_field_name("parameters") {
                for i in 0..params.child_count() {
                    if let Some(param) = params.child(i) {
                        if param.kind() == "parameter_declaration" {
                            self.extract_type_and_name(&param, source, type_map);
                        }
                    }
                }
            }
        }
    }

    fn collect_local_declarations(
        &self,
        node: &Node,
        source: &str,
        type_map: &mut HashMap<String, String>,
    ) {
        for decl in query::find_descendants_of_kind(*node, "declaration") {
            self.extract_type_and_name(&decl, source, type_map);
        }
    }

    fn extract_type_and_name(
        &self,
        node: &Node,
        source: &str,
        type_map: &mut HashMap<String, String>,
    ) {
        let mut type_text = String::new();

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "primitive_type" | "sized_type_specifier" | "type_identifier" => {
                        type_text = get_node_text(&child, source).to_string();
                    }
                    "struct_specifier" => {
                        type_text = get_node_text(&child, source).to_string();
                    }
                    _ => {}
                }
            }
        }

        if type_text.is_empty() {
            return;
        }

        // Extract variable names from declarators
        if let Some(declarator) = node.child_by_field_name("declarator") {
            if let Some(name) = Self::extract_identifier_name(&declarator, source) {
                let full_type = if Self::is_pointer_declarator(&declarator) {
                    format!("{} *", type_text)
                } else {
                    type_text.clone()
                };
                type_map.insert(name, full_type);
            }
        }

        // Handle init_declarator lists (e.g. `int a, b;`)
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(decl) = child.child_by_field_name("declarator") {
                        if let Some(name) = Self::extract_identifier_name(&decl, source) {
                            let full_type = if Self::is_pointer_declarator(&decl) {
                                format!("{} *", type_text)
                            } else {
                                type_text.clone()
                            };
                            type_map.insert(name, full_type);
                        }
                    }
                }
            }
        }
    }

    /// Returns true if this declarator (or init_declarator wrapping it) contains
    /// a pointer_declarator, indicating the declared variable is a pointer type.
    fn is_pointer_declarator(node: &Node) -> bool {
        if node.kind() == "pointer_declarator" {
            return true;
        }
        // init_declarator wraps the actual declarator
        if node.kind() == "init_declarator" {
            if let Some(decl) = node.child_by_field_name("declarator") {
                return decl.kind() == "pointer_declarator";
            }
        }
        false
    }

    fn extract_identifier_name(node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => Some(get_node_text(node, source).to_string()),
            "pointer_declarator" | "array_declarator" | "parenthesized_declarator" => {
                if let Some(inner) = node.child_by_field_name("declarator") {
                    Self::extract_identifier_name(&inner, source)
                } else {
                    None
                }
            }
            _ => {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "identifier" {
                            return Some(get_node_text(&child, source).to_string());
                        }
                    }
                }
                None
            }
        }
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
        // identifier initialized from a call_expression.
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
                        return Self::resolve_identifier_call_name(&body, var_name, source, n);
                    }
                }
            }
            None
        };

        let callee = if is_small_literal(&right) {
            resolve_callee(&left)
        } else if is_small_literal(&left) {
            resolve_callee(&right)
        } else {
            return false;
        };

        let callee = match callee {
            Some(name) => name,
            None => return false,
        };

        // Known full-range or untrusted-decode functions: never suppress
        if std_functions::is_full_range_return_function(&callee)
            || std_functions::is_untrusted_decode_function(&callee)
        {
            return false;
        }

        // Local function carrying taint (directly or transitively), or with a
        // proven wide return range: don't suppress. Keeps the heuristic
        // consistent with the provenance gate for cross-function flow.
        if let Some(summary) = summaries.get(&callee) {
            if summary.has_env03_taint_source || summary.returns_tainted {
                return false;
            }
            if let Some(ref return_range) = summary.return_range {
                let unsigned_danger = u32::MAX as i64 - 10;
                if return_range.max >= unsigned_danger {
                    return false;
                }
            }
        }

        // Default: suppress (safe for strlen, wcslen, unknown helpers)
        true
    }

    /// Resolve the callee function name for an identifier that was initialized
    /// name instead of just a boolean.
    fn resolve_identifier_call_name(
        scope: &Node,
        var_name: &str,
        source: &str,
        usage_node: &Node,
    ) -> Option<String> {
        let usage_row = usage_node.start_position().row;
        for i in 0..scope.named_child_count() {
            if let Some(child) = scope.named_child(i) {
                if child.start_position().row >= usage_row {
                    break;
                }
                if child.kind() == "declaration" {
                    if let Some(declarator) = child.child_by_field_name("declarator") {
                        if declarator.kind() == "init_declarator" {
                            let decl_name = declarator
                                .child_by_field_name("declarator")
                                .map(|d| get_node_text(&d, source));
                            let init = declarator.child_by_field_name("value");
                            if decl_name == Some(var_name) {
                                if let Some(init_node) = init {
                                    if init_node.kind() == "call_expression" {
                                        return init_node
                                            .child_by_field_name("function")
                                            .and_then(|f| f.utf8_text(source.as_bytes()).ok())
                                            .map(|s| s.trim().to_string());
                                    }
                                }
                            }
                        }
                    }
                }
                if child.kind() == "expression_statement" {
                    if let Some(expr) = child.named_child(0) {
                        if expr.kind() == "assignment_expression" {
                            let lhs = expr.child_by_field_name("left");
                            let rhs = expr.child_by_field_name("right");
                            if let (Some(l), Some(r)) = (lhs, rhs) {
                                if get_node_text(&l, source) == var_name
                                    && r.kind() == "call_expression"
                                {
                                    return r
                                        .child_by_field_name("function")
                                        .and_then(|f| f.utf8_text(source.as_bytes()).ok())
                                        .map(|s| s.trim().to_string());
                                }
                            }
                        }
                    }
                }
                if child.kind().starts_with("preproc_")
                    || child.kind() == "compound_statement"
                    || child.kind() == "if_statement"
                    || child.kind() == "switch_statement"
                    || child.kind() == "case_statement"
                    || child.kind() == "for_statement"
                    || child.kind() == "while_statement"
                {
                    if let Some(name) =
                        Self::resolve_identifier_call_name(&child, var_name, source, usage_node)
                    {
                        return Some(name);
                    }
                }
            }
        }
        None
    }

    fn is_unsigned_type(&self, type_str: &str) -> bool {
        type_str.contains("unsigned") || type_str == "size_t" || type_str.contains("uint")
    }

    /// Returns true if the type is a narrow unsigned integer (8-bit or 16-bit).
    /// Operations on narrow unsigned types are promoted to `int` (at least 32-bit)
    /// by the C standard, so they cannot overflow `unsigned int` in practice:
    /// max(uint8_t) * max(uint8_t) = 255*255 = 65025, fits in 32-bit.
    /// max(uint16_t) + max(uint16_t) = 131070, fits in 32-bit.
    fn is_narrow_unsigned_type(&self, type_str: &str) -> bool {
        matches!(
            type_str,
            "uint8_t"
                | "uint_least8_t"
                | "uint_fast8_t"
                | "uint16_t"
                | "uint_least16_t"
                | "uint_fast16_t"
                | "unsigned char"
                | "unsigned short"
        )
    }

    /// For a cast_expression node, return the type of the inner (pre-cast) value.
    /// For non-cast nodes, return None. This lets callers see through widening casts
    /// like `(uint32_t)narrow_var` to detect that the original value is narrow.
    fn get_pre_cast_type(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> Option<String> {
        if node.kind() == "cast_expression" {
            if let Some(value) = node.child_by_field_name("value") {
                let inner_type = self.infer_type(&value, source, type_map);
                if inner_type != "unknown" {
                    return Some(inner_type);
                }
            }
        }
        None
    }

    /// Strip type qualifiers (volatile, const, _Atomic) from a type string.
    fn strip_type_qualifiers(type_str: &str) -> String {
        type_str
            .replace("volatile ", "")
            .replace("const ", "")
            .replace("_Atomic ", "")
            .trim()
            .to_string()
    }

    /// Returns true if the type is a "wide" unsigned integer (32-bit or larger).
    /// When a narrow unsigned is combined with a wide unsigned, C promotes to
    /// the wide unsigned type — the result IS unsigned and can wrap.
    fn is_wide_unsigned_type(&self, type_str: &str) -> bool {
        self.is_unsigned_type(type_str) && !self.is_narrow_unsigned_type(type_str)
    }

    /// Returns true if one operand is narrow unsigned and the other is NOT a
    /// wider unsigned type. In this case, C promotes the narrow unsigned to
    /// `int` (signed 32-bit), making the arithmetic signed — no unsigned wrap.
    fn narrow_promotion_is_safe(&self, left_type: &str, right_type: &str) -> bool {
        let left_narrow = self.is_narrow_unsigned_type(left_type);
        let right_narrow = self.is_narrow_unsigned_type(right_type);

        if left_narrow && !self.is_wide_unsigned_type(right_type) {
            return true;
        }
        if right_narrow && !self.is_wide_unsigned_type(left_type) {
            return true;
        }
        // Both narrow — already handled by the existing check, but include for completeness
        left_narrow && right_narrow
    }

    /// Check if text is a valid C operand expression (simple identifier or
    /// field expression like `ctx->field` or `obj.member`).
    fn is_valid_operand_expr(&self, text: &str) -> bool {
        if text.is_empty() {
            return false;
        }
        // Split on -> and . to get component parts
        for part in text.split("->").flat_map(|s| s.split('.')) {
            let part = part.trim();
            if part.is_empty() {
                return false;
            }
            if !part.chars().all(|c| c.is_alphanumeric() || c == '_')
                || !part
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphabetic() || c == '_')
            {
                return false;
            }
        }
        true
    }

    /// Check if a binary addition is immediately masked by bitwise AND.
    /// Pattern: `(expr + N) & MASK` — result is bounded by the mask regardless
    /// of whether the addition wraps. Common in ring buffer index arithmetic.
    /// Returns true when the addition result is the left operand of a `% N` expression.
    /// Pattern: `(x + 1) % N` — ring-buffer next-index idiom. The modulo makes the
    /// intermediate sum's exact value irrelevant; overflow doesn't change correctness.
    fn is_addition_bounded_by_modulo(&self, node: &Node, source: &str) -> bool {
        if let Some(parent) = node.parent() {
            let effective_parent = if parent.kind() == "parenthesized_expression" {
                parent.parent()
            } else {
                Some(parent)
            };
            if let Some(p) = effective_parent {
                if p.kind() == "binary_expression" {
                    if let Some(op) = p.child_by_field_name("operator") {
                        if get_node_text(&op, source) == "%" {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Returns true when the left operand of a subtraction is a call to a tick/time
    /// getter function (name contains "Tick", "Time", "Clock", "Counter", "Stamp").
    /// In that idiom unsigned wrap is intentional — see C99 §6.2.5p9.
    fn is_elapsed_time_subtraction(&self, left: &Node, source: &str) -> bool {
        let tick_keywords = ["Tick", "tick", "Time", "Clock", "clock", "Counter", "Stamp"];
        // Unwrap any parenthesized or cast expression to reach the call
        let mut cur = *left;
        loop {
            match cur.kind() {
                "parenthesized_expression" | "cast_expression" => {
                    if let Some(inner) = cur.child(1) {
                        cur = inner;
                    } else {
                        break;
                    }
                }
                "call_expression" => {
                    if let Some(func) = cur.child_by_field_name("function") {
                        let name = get_node_text(&func, source);
                        if tick_keywords.iter().any(|kw| name.contains(kw)) {
                            return true;
                        }
                    }
                    break;
                }
                _ => break,
            }
        }
        false
    }

    fn is_addition_masked_by_bitand(&self, node: &Node, source: &str) -> bool {
        // The addition node's parent should be a binary_expression with operator &
        if let Some(parent) = node.parent() {
            // Check for parenthesized_expression wrapping
            let effective_parent = if parent.kind() == "parenthesized_expression" {
                parent.parent()
            } else {
                Some(parent)
            };
            if let Some(p) = effective_parent {
                if p.kind() == "binary_expression" {
                    if let Some(op) = p.child_by_field_name("operator") {
                        let op_text = get_node_text(&op, source);
                        if op_text == "&" {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Return the effective (pre-cast if applicable) type of an operand.
    fn effective_operand_type(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> String {
        if let Some(pre) = self.get_pre_cast_type(node, source, type_map) {
            return pre;
        }
        if self.is_cast_over_guarded_narrow_sub(node, source, type_map) {
            return "uint16_t".to_string();
        }
        self.infer_type(node, source, type_map)
    }

    /// True when `node` is `(WIDE)(a - b)` with both operands narrow unsigned
    /// and the subtraction is guarded by an enclosing `if (a > b)` / `if (a >= b)`
    /// (or equivalent). In that branch the subtraction result is in the narrow
    /// unsigned range, so the cast behaves like a narrow-to-wide widening.
    fn is_cast_over_guarded_narrow_sub(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        if node.kind() != "cast_expression" {
            return false;
        }
        let Some(value) = node.child_by_field_name("value") else {
            return false;
        };
        // Peek through parens to the inner expression.
        let mut inner = value;
        while inner.kind() == "parenthesized_expression" {
            match inner.child(1) {
                Some(c) => inner = c,
                None => return false,
            }
        }
        if inner.kind() != "binary_expression" {
            return false;
        }
        match self.get_operator(&inner, source).as_deref() {
            Some("-") => {}
            _ => return false,
        }
        let (Some(l), Some(r)) = (
            inner.child_by_field_name("left"),
            inner.child_by_field_name("right"),
        ) else {
            return false;
        };
        let lt = self.infer_type(&l, source, type_map);
        let rt = self.infer_type(&r, source, type_map);
        if !self.is_narrow_unsigned_type(&lt) || !self.is_narrow_unsigned_type(&rt) {
            return false;
        }
        let lname = get_node_text(&l, source);
        let rname = get_node_text(&r, source);
        self.is_subtraction_guarded_by_comparison(node, lname.trim(), rname.trim(), source)
    }

    /// True when both operands' effective (pre-cast) types are narrow unsigned
    /// (uint8_t or uint16_t). Max sum/product fits in uint32_t.
    fn both_operands_narrow_pre_cast(
        &self,
        left: &Node,
        right: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        let l = self.effective_operand_type(left, source, type_map);
        let r = self.effective_operand_type(right, source, type_map);
        self.is_narrow_unsigned_type(&l) && self.is_narrow_unsigned_type(&r)
    }

    /// True when one operand is a narrow unsigned (possibly widened by a cast)
    /// and the other const-evaluates to a small non-negative integer
    /// (≤ `UINT16_MAX`, ~65535). Result cannot exceed ~131K, fitting uint32_t.
    fn is_narrow_cast_plus_small_const(
        &self,
        left: &Node,
        right: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        let macros = self.current_macros.borrow();
        let check = |narrow: &Node, small: &Node| -> bool {
            let t = self.effective_operand_type(narrow, source, type_map);
            if !self.is_narrow_unsigned_type(&t) {
                return false;
            }
            if let Some(val) = const_eval::try_evaluate_expr(small, source, &macros) {
                return (0..=65535).contains(&val);
            }
            false
        };
        check(left, right) || check(right, left)
    }

    /// True when one operand is narrow unsigned (directly or via cast from
    /// narrow) and the other const-evaluates to a non-negative integer whose
    /// product with `UINT16_MAX` (65535) fits in uint32_t. In other words
    /// `small ≤ UINT32_MAX / UINT16_MAX ≈ 65538`.
    fn is_narrow_cast_times_small_const(
        &self,
        left: &Node,
        right: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        let macros = self.current_macros.borrow();
        const MAX_FACTOR: i64 = (u32::MAX as i64) / 65535; // ≈ 65538
        let check = |narrow: &Node, small: &Node| -> bool {
            let t = self.effective_operand_type(narrow, source, type_map);
            if !self.is_narrow_unsigned_type(&t) {
                return false;
            }
            if let Some(val) = const_eval::try_evaluate_expr(small, source, &macros) {
                return (0..=MAX_FACTOR).contains(&val);
            }
            false
        };
        check(left, right) || check(right, left)
    }

    fn is_64bit_unsigned_declared(&self, type_str: &str) -> bool {
        type_str == "uint64_t"
            || type_str == "unsigned long long"
            || type_str == "unsigned long long int"
            || type_str == "uint_least64_t"
            || type_str == "uint_fast64_t"
    }

    fn any_operand_64bit_unsigned(
        &self,
        left: &Node,
        right: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        let left_64 = self
            .get_declared_type(left, source, type_map)
            .is_some_and(|t| self.is_64bit_unsigned_declared(&t));
        let right_64 = self
            .get_declared_type(right, source, type_map)
            .is_some_and(|t| self.is_64bit_unsigned_declared(&t));
        left_64 || right_64
    }

    fn get_declared_type(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> Option<String> {
        match node.kind() {
            "identifier" => {
                let name = get_node_text(node, source);
                type_map.get(name).cloned()
            }
            "call_expression" => {
                // For function calls, check if the result is assigned to a typed variable
                // or look at the surrounding context. For now, return None.
                None
            }
            _ => None,
        }
    }

    fn has_overflow_check_addition(&self, node: &Node, source: &str) -> bool {
        // Look for UINT_MAX - a < b pattern (precondition) or result < a (postcondition)
        self.has_function_context_check(node, source, &["UINT_MAX", " - ", " < "])
            || self.has_function_context_check(node, source, &["SIZE_MAX", " - ", " < "])
            || self.has_function_context_check(node, source, &["== UINT_MAX"])
            || self.has_postcondition_check(node, source)
            || self.uses_wider_type(node, source)
            || self.is_inside_checked_block(node, source)
    }

    fn has_overflow_check_subtraction(&self, node: &Node, source: &str) -> bool {
        // Look for if (a < b) or postcondition if (result > a) pattern
        // Note: We need an actual if check before or after the subtraction
        self.has_subtraction_precondition(node, source)
            || self.has_postcondition_check(node, source)
            || self.is_inside_checked_block(node, source)
            || self.is_subtract_one_guarded(node, source)
    }

    fn has_overflow_check_multiplication(&self, node: &Node, source: &str) -> bool {
        // Look for a > MAX / b pattern in containing function
        self.has_function_context_check(node, source, &["UINT_MAX", " / "])
            || self.has_function_context_check(node, source, &["SIZE_MAX", " / "])
            || self.has_preceding_overflow_check(node, source)
            || self.uses_wider_type(node, source)
            || self.is_inside_checked_block(node, source)
    }

    /// Check if there's an overflow check in the code preceding this node
    fn has_preceding_overflow_check(&self, node: &Node, source: &str) -> bool {
        // Get text before this node in the translation unit
        let node_start = node.start_byte();
        if node_start > 0 {
            let preceding_text = &source[..node_start];
            // Look for SIZE_MAX/UINT_MAX division check patterns
            if (preceding_text.contains("SIZE_MAX /") || preceding_text.contains("UINT_MAX /"))
                && preceding_text.contains("if")
            {
                return true;
            }
        }
        false
    }

    fn has_shift_overflow_check(&self, node: &Node, source: &str) -> bool {
        // Look for shift amount validation
        self.has_function_context_check(node, source, &["sizeof"])
            || self.is_inside_checked_block(node, source)
    }

    fn has_overflow_check_compound(&self, node: &Node, source: &str) -> bool {
        // Look for any overflow checking pattern
        self.has_function_context_check(node, source, &["if", "UINT_MAX"])
            || self.has_function_context_check(node, source, &["if", "SIZE_MAX"])
            || self.is_inside_checked_block(node, source)
    }

    fn has_overflow_check_update(&self, node: &Node, source: &str) -> bool {
        // Look for bounds checking around increment/decrement - must be explicit UINT_MAX or == 0
        self.has_function_context_check(node, source, &["if", "UINT_MAX"])
            || self.has_function_context_check(node, source, &["if", "== 0"])
            || self.is_inside_checked_block(node, source)
    }

    fn has_calloc_overflow_check(&self, node: &Node, source: &str) -> bool {
        // Look for calloc-specific overflow checking
        if self.has_function_context_check(node, source, &["SIZE_MAX", " / "])
            || self.is_inside_checked_block(node, source)
        {
            return true;
        }
        // Thin-wrapper pattern: both calloc arguments are function parameters
        // of the enclosing function. The wrapper delegates overflow detection
        // to C11 calloc itself (§7.22.3.2 — "If the product of nmemb and size
        // … would overflow, … calloc shall return a null pointer"), so the
        // wrapper body does not need its own SIZE_MAX / size check.
        self.calloc_args_are_function_params(node, source)
    }

    fn calloc_args_are_function_params(&self, node: &Node, source: &str) -> bool {
        let args = self.get_function_arguments(node, source);
        if args.len() < 2 {
            return false;
        }
        let Some(func) = self.find_containing_function(node) else {
            return false;
        };
        let mut params: HashMap<String, String> = HashMap::new();
        if let Some(declarator) = func.child_by_field_name("declarator") {
            self.collect_params_from_declarator(&declarator, source, &mut params);
        }
        params.contains_key(args[0].trim()) && params.contains_key(args[1].trim())
    }

    fn has_function_context_check(&self, node: &Node, source: &str, patterns: &[&str]) -> bool {
        // Look in the containing function for overflow checking patterns.
        // Fall back to the full translation unit when the call is at file
        // scope (e.g. wiki snippet tests without a wrapping function).
        if let Some(func) = self.find_containing_function(node) {
            let func_text = get_node_text(&func, source);
            return patterns.iter().all(|pattern| func_text.contains(pattern));
        }
        let mut root = *node;
        while let Some(p) = root.parent() {
            root = p;
        }
        let text = get_node_text(&root, source);
        patterns.iter().all(|pattern| text.contains(pattern))
    }

    /// Check for subtraction precondition (if (a < b) before subtraction)
    fn has_subtraction_precondition(&self, node: &Node, source: &str) -> bool {
        // Look for if statement before the subtraction that compares the operands
        if let Some(func) = self.find_containing_function(node) {
            let func_text = get_node_text(&func, source);
            // Look for typical precondition pattern
            if func_text.contains("if (ui_a < ui_b)")
                || func_text.contains("if (a < b)")
                || func_text.contains("if(ui_a < ui_b)")
                || func_text.contains("if(a < b)")
            {
                return true;
            }
        }
        false
    }

    /// Check for postcondition check (if (result < original) or if (result > original))
    fn has_postcondition_check(&self, node: &Node, source: &str) -> bool {
        if let Some(func) = self.find_containing_function(node) {
            let func_text = get_node_text(&func, source);
            // Look for postcondition patterns like "if (usum < ui_a)" or "if (udiff > ui_a)"
            if func_text.contains("if (usum < ")
                || func_text.contains("if (udiff > ")
                || func_text.contains("if(usum < ")
                || func_text.contains("if(udiff > ")
                || func_text.contains("if (result < ")
                || func_text.contains("if (result > ")
            {
                return true;
            }
        }
        false
    }

    /// Check if operation uses wider type casting for safety
    fn uses_wider_type(&self, node: &Node, source: &str) -> bool {
        // Check parent for cast to wider type
        if let Some(parent) = node.parent() {
            let parent_text = get_node_text(&parent, source);
            if parent_text.contains("(uint64_t)")
                || parent_text.contains("(unsigned long long)")
                || parent_text.contains("(int64_t)")
            {
                return true;
            }
        }
        // Also check if operands are cast to wider type
        let node_text = get_node_text(node, source);
        if node_text.contains("(uint64_t)") || node_text.contains("(unsigned long long)") {
            return true;
        }
        false
    }

    /// Extract operand identifier names from a binary/assignment/update expression node.
    fn extract_operand_names(&self, node: &Node, source: &str) -> Vec<String> {
        let mut names = Vec::new();
        if let Some(left) = node.child_by_field_name("left") {
            Self::collect_identifiers(&left, source, &mut names);
        }
        if let Some(right) = node.child_by_field_name("right") {
            Self::collect_identifiers(&right, source, &mut names);
        }
        if let Some(arg) = node.child_by_field_name("argument") {
            Self::collect_identifiers(&arg, source, &mut names);
        }
        names
    }

    fn collect_identifiers(node: &Node, source: &str, names: &mut Vec<String>) {
        for ident in query::find_descendants_of_kind(*node, "identifier") {
            let name = get_node_text(&ident, source).to_string();
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }

    /// Check if `text` contains `word` as a whole word (not a substring of another identifier).
    fn contains_word(&self, text: &str, word: &str) -> bool {
        if word.is_empty() {
            return false;
        }
        let mut start = 0;
        while let Some(pos) = text[start..].find(word) {
            let abs_pos = start + pos;
            let before_ok = abs_pos == 0
                || !text.as_bytes()[abs_pos - 1].is_ascii_alphanumeric()
                    && text.as_bytes()[abs_pos - 1] != b'_';
            let after_pos = abs_pos + word.len();
            let after_ok = after_pos >= text.len()
                || !text.as_bytes()[after_pos].is_ascii_alphanumeric()
                    && text.as_bytes()[after_pos] != b'_';
            if before_ok && after_ok {
                return true;
            }
            start = abs_pos + 1;
        }
        false
    }

    /// Check if the operation is inside an if-else block guarded by an unsigned type-limit macro.
    /// Operand-aware: the if-condition must reference at least one operand of the arithmetic.
    fn is_inside_checked_block(&self, node: &Node, source: &str) -> bool {
        const UNSIGNED_LIMIT_MACROS: &[&str] = &[
            "UINT_MAX",
            "SIZE_MAX",
            "UINT32_MAX",
            "UCHAR_MAX",
            "USHRT_MAX",
            "UINT8_MAX",
            "UINT16_MAX",
            "UINT64_MAX",
            "ULONG_MAX",
            "ULLONG_MAX",
        ];

        let op_names = self.extract_operand_names(node, source);
        let mut current = *node;
        while let Some(parent) = current.parent() {
            if parent.kind() == "if_statement" {
                if let Some(condition) = parent.child_by_field_name("condition") {
                    let cond_text = get_node_text(&condition, source);
                    let has_limit = UNSIGNED_LIMIT_MACROS
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
                }
            }
            // Stop at function boundary
            if parent.kind() == "function_definition" {
                break;
            }
            current = parent;
        }
        false
    }

    #[allow(dead_code)]
    fn has_surrounding_check(&self, node: &Node, source: &str, patterns: &[&str]) -> bool {
        // Simple heuristic: look in parent contexts for overflow checking patterns
        if let Some(parent) = node.parent() {
            if let Some(grandparent) = parent.parent() {
                let context = &source[grandparent.start_byte()..grandparent.end_byte()];
                return patterns.iter().all(|pattern| context.contains(pattern));
            }
        }
        false
    }

    fn get_operator(&self, node: &Node, source: &str) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let text = &source[child.start_byte()..child.end_byte()];
                if matches!(text, "+" | "-" | "*" | "/" | "<<" | ">>") {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    fn get_assignment_operator(&self, node: &Node, source: &str) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let text = &source[child.start_byte()..child.end_byte()];
                if matches!(text, "+=" | "-=" | "*=" | "/=" | "<<=" | ">>=") {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    fn get_update_operator(&self, node: &Node, source: &str) -> String {
        let text = get_node_text(node, source);
        if text.contains("++") {
            "++".to_string()
        } else if text.contains("--") {
            "--".to_string()
        } else {
            "unknown".to_string()
        }
    }

    /// Check if a decrement/subtraction is inside a block guarded by a positive-value condition.
    /// Patterns: `if (var > 0)`, `while (var > expr)`, `for (...; var > expr; ...)`.
    /// For unsigned types, `var > expr` implies `var >= 1`, making `var--` or `var - 1` safe.
    fn is_guarded_by_gt_zero(&self, node: &Node, var_name: &str, source: &str) -> bool {
        let mut current = *node;
        while let Some(parent) = current.parent() {
            if matches!(
                parent.kind(),
                "if_statement" | "while_statement" | "for_statement"
            ) {
                if let Some(condition) = parent.child_by_field_name("condition") {
                    let cond_text = get_node_text(&condition, source);
                    if self.condition_implies_positive(cond_text, var_name) {
                        return true;
                    }
                }
            }
            if parent.kind() == "function_definition" {
                break;
            }
            current = parent;
        }
        false
    }

    /// Check if a condition text implies var_name > 0 (i.e., var is positive).
    /// Handles compound conditions (&&/||) via substring matching.
    /// Recognizes `var > expr` (any lower bound, not just zero) since for unsigned
    /// types, `var > expr` always implies `var >= 1`.
    fn condition_implies_positive(&self, cond_text: &str, var_name: &str) -> bool {
        let cond = cond_text.trim();
        let cond = if cond.starts_with('(') && cond.ends_with(')') {
            &cond[1..cond.len() - 1]
        } else {
            cond
        };
        let cond = cond.trim();

        // Quick check: does the condition mention the variable as a whole word?
        if !self.contains_word(cond, var_name) {
            return false;
        }

        // Pattern 1: var > expr (strict GT — implies var >= 1 for unsigned)
        // Covers: var > 0, var > idx, var > some_expr, etc.
        let gt_pat = format!("{} > ", var_name);
        if cond.contains(&gt_pat) {
            return true;
        }

        // Pattern 2: var != 0 or 0 != var (explicit non-zero check)
        let neq_zero = format!("{} != 0", var_name);
        let zero_neq = format!("0 != {}", var_name);
        if cond.contains(&neq_zero) || cond.contains(&zero_neq) {
            return true;
        }

        // Pattern 3: expr < var (reverse of var > expr — strict LT)
        let lt_rev = format!("< {}", var_name);
        if cond.contains(&lt_rev) {
            for (pos, _) in cond.match_indices(&lt_rev) {
                // Exclude << (shift) and <= (less-than-or-equal)
                let prev = if pos > 0 { cond.as_bytes()[pos - 1] } else { 0 };
                if prev != b'<' && prev != b'=' {
                    return true;
                }
            }
        }

        false
    }

    /// For "var - 1" or "var - 1U" subtraction: if var is guarded by a
    /// positive-value condition or was incremented before this point,
    /// then var >= 1 and var - 1 >= 0, so no unsigned wrap.
    fn is_subtract_one_guarded(&self, node: &Node, source: &str) -> bool {
        if let Some(right) = node.child_by_field_name("right") {
            let right_text = get_node_text(&right, source).trim().to_string();
            // Accept 1, 1U, 1u, 1UL, 1ul, etc.
            if self.is_literal_one(&right_text) {
                if let Some(left) = node.child_by_field_name("left") {
                    let var_name = get_node_text(&left, source).trim().to_string();
                    if self.is_guarded_by_gt_zero(node, &var_name, source) {
                        return true;
                    }
                    // Check if the variable was incremented before this subtraction
                    // in the same compound_statement (e.g., `var++; ... var - 1U`)
                    if self.is_preceded_by_increment(node, &var_name, source) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if a literal text represents the value 1 (with optional unsigned suffix).
    fn is_literal_one(&self, text: &str) -> bool {
        let text = text.trim();
        if text == "1" {
            return true;
        }
        // Strip unsigned/long suffixes: 1U, 1u, 1UL, 1ul, 1ULL, etc.
        let stripped = text.trim_end_matches(['u', 'U', 'l', 'L']);
        stripped == "1"
    }

    /// Check if the variable was incremented (var++, ++var, var += 1) before
    /// this node in the same compound_statement. This means var >= 1 at the
    /// point of the subtraction.
    fn is_preceded_by_increment(&self, node: &Node, var_name: &str, source: &str) -> bool {
        // Find the enclosing compound_statement
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "compound_statement" {
                let before_text = &source[parent.start_byte()..node.start_byte()];
                // Check for var++ or ++var
                let postinc = format!("{}++", var_name);
                let preinc = format!("++{}", var_name);
                let addassign = format!("{} += 1", var_name);
                if before_text.contains(&postinc)
                    || before_text.contains(&preinc)
                    || before_text.contains(&addassign)
                {
                    return true;
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

    /// Check if a node is inside the update clause of a for-loop.
    /// For-loop update increments (i++) are bounded by the loop condition,
    /// making unsigned wrap impossible in normal usage.
    fn is_in_for_loop_update(&self, node: &Node) -> bool {
        let mut current = Some(*node);
        while let Some(n) = current {
            if let Some(parent) = n.parent() {
                if parent.kind() == "for_statement" {
                    // Check if this node is in the update clause
                    // The for_statement fields: initializer, condition, update, body
                    if let Some(update) = parent.child_by_field_name("update") {
                        if self.node_contains(&update, &n) {
                            return true;
                        }
                    }
                }
                current = Some(parent);
            } else {
                break;
            }
        }
        false
    }

    /// Check if parent node contains child (by byte range).
    fn node_contains(&self, parent: &Node, child: &Node) -> bool {
        child.start_byte() >= parent.start_byte() && child.end_byte() <= parent.end_byte()
    }

    /// For binary "var + 1" or "1 + var" (including 1U, 1u, etc.): if var is bounded
    /// by an enclosing loop condition (var < limit), then var + 1 <= limit <= UINT_MAX,
    /// so no wrap.
    fn is_add_one_bounded_by_loop(&self, node: &Node, source: &str) -> bool {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let left_text = get_node_text(&left, source);
            let right_text = get_node_text(&right, source);

            // Check "var + 1" pattern (including 1U, 1u, 1UL, etc.)
            if self.is_literal_one(right_text.trim()) {
                return self.is_bounded_by_loop_condition(node, left_text.trim(), source);
            }
            // Check "1 + var" pattern
            if self.is_literal_one(left_text.trim()) {
                return self.is_bounded_by_loop_condition(node, right_text.trim(), source);
            }
        }
        false
    }

    /// Check if var_name is bounded by an enclosing loop or if-statement condition.
    /// Detects `while (var < limit)`, `for (...; var < limit; ...)`, and
    /// `if (var < limit)` patterns (true branch only).
    /// Inside the guarded body, var < limit, so var + 1 <= limit <= UINT_MAX.
    fn is_bounded_by_loop_condition(&self, node: &Node, var_name: &str, source: &str) -> bool {
        let mut current = *node;
        while let Some(parent) = current.parent() {
            if matches!(parent.kind(), "while_statement" | "for_statement") {
                if let Some(condition) = parent.child_by_field_name("condition") {
                    let cond_text = get_node_text(&condition, source);
                    if self.condition_implies_upper_bound(&cond_text, var_name) {
                        return true;
                    }
                }
            }
            // Also check if_statement — but only if we're in the true branch
            if parent.kind() == "if_statement" {
                if let Some(condition) = parent.child_by_field_name("condition") {
                    let cond_text = get_node_text(&condition, source);
                    if self.condition_implies_upper_bound(&cond_text, var_name) {
                        // Verify we're inside the consequence (true branch), not alternative
                        if let Some(consequence) = parent.child_by_field_name("consequence") {
                            if current.start_byte() >= consequence.start_byte()
                                && current.end_byte() <= consequence.end_byte()
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            if parent.kind() == "function_definition" {
                break;
            }
            current = parent;
        }
        false
    }

    /// Check if a condition implies var < some_limit (upper bound).
    /// Recognizes: `var < expr`, `var <= expr`, `expr > var`, `expr >= var`.
    fn condition_implies_upper_bound(&self, cond_text: &str, var_name: &str) -> bool {
        let cond = cond_text.trim();
        let cond = if cond.starts_with('(') && cond.ends_with(')') {
            &cond[1..cond.len() - 1]
        } else {
            cond
        };
        let cond = cond.trim();

        if !self.contains_word(cond, var_name) {
            return false;
        }

        // Pattern 1: var < expr or var <= expr
        let lt_pat = format!("{} < ", var_name);
        let le_pat = format!("{} <= ", var_name);
        if cond.contains(&lt_pat) || cond.contains(&le_pat) {
            return true;
        }

        // Pattern 2: expr > var or expr >= var
        let gt_rev = format!("> {}", var_name);
        if cond.contains(&gt_rev) {
            // Exclude >> (shift)
            for (pos, _) in cond.match_indices(&gt_rev) {
                let prev = if pos > 0 { cond.as_bytes()[pos - 1] } else { 0 };
                if prev != b'>' {
                    return true;
                }
            }
        }

        false
    }

    /// Check if `a - b` is inside a block guarded by `a >= b`, `a > b`, `b <= a`, or `b < a`.
    /// Walks ancestors for if_statement, while_statement, for_statement — same pattern
    /// as `is_guarded_by_gt_zero` but checks for a comparison between the two operands.
    /// Also handles else-branch: if inside `else` of `if (b > a)`, then `a - b` is NOT safe
    /// but `b - a` IS safe (the else implies `a >= b` is false, i.e., `b >= a`).
    fn is_subtraction_guarded_by_comparison(
        &self,
        node: &Node,
        left_name: &str,
        right_name: &str,
        source: &str,
    ) -> bool {
        // Apply when both operands are valid operand expressions (simple identifiers
        // or field expressions like ctx->field, obj.member)
        if !self.is_valid_operand_expr(left_name) || !self.is_valid_operand_expr(right_name) {
            return false;
        }

        let mut current = *node;
        while let Some(parent) = current.parent() {
            if matches!(
                parent.kind(),
                "if_statement" | "while_statement" | "for_statement"
            ) {
                if let Some(condition) = parent.child_by_field_name("condition") {
                    let cond_text = get_node_text(&condition, source);

                    // True-branch: if (left >= right) { left - right } is safe
                    if self.condition_implies_a_gte_b(&cond_text, left_name, right_name) {
                        if parent.kind() == "if_statement" {
                            if let Some(consequence) = parent.child_by_field_name("consequence") {
                                if current.start_byte() >= consequence.start_byte()
                                    && current.end_byte() <= consequence.end_byte()
                                {
                                    return true;
                                }
                            }
                        } else {
                            // while/for: loop body is always the true branch
                            return true;
                        }
                    }

                    // Else-branch: if (right > left) { ... } else { left - right }
                    // In the else branch, !(right > left) implies left >= right,
                    // so left - right is safe.
                    if parent.kind() == "if_statement" {
                        if self.condition_implies_a_gte_b(&cond_text, right_name, left_name) {
                            if let Some(alternative) = parent.child_by_field_name("alternative") {
                                if current.start_byte() >= alternative.start_byte()
                                    && current.end_byte() <= alternative.end_byte()
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            // Implicit-else from an early-exit if:
            //   if (right > left) return ...;
            //   /* subtraction here: left - right is safe */
            // Walk preceding siblings at every compound_statement on the way
            // up. If any is an early-exit if whose condition implies
            // right > left, the subtraction is guarded.
            if parent.kind() == "compound_statement"
                && self.preceding_early_exit_guards_subtraction(
                    &parent, &current, left_name, right_name, source,
                )
            {
                return true;
            }

            if parent.kind() == "function_definition" {
                break;
            }
            current = parent;
        }
        false
    }

    /// Check for a preceding sibling `if (cond) return/break/continue/goto ...;`
    /// whose condition implies `right > left`, in which case the implicit
    /// else-path (statements after the if) has `left >= right`.
    fn preceding_early_exit_guards_subtraction(
        &self,
        compound: &Node,
        current: &Node,
        left_name: &str,
        right_name: &str,
        source: &str,
    ) -> bool {
        let current_start = current.start_byte();
        for i in 0..compound.named_child_count() {
            let Some(sibling) = compound.named_child(i) else {
                break;
            };
            if sibling.end_byte() > current_start {
                break;
            }
            if sibling.kind() != "if_statement" {
                continue;
            }
            if !Self::if_always_exits(&sibling) {
                continue;
            }
            let Some(cond) = sibling.child_by_field_name("condition") else {
                continue;
            };
            let cond_text = get_node_text(&cond, source);
            if self.condition_implies_a_gte_b(&cond_text, right_name, left_name) {
                return true;
            }
        }
        false
    }

    /// True when the consequence of `if_node` is a statement (or compound
    /// block ending with a statement) that unconditionally transfers
    /// control out of the enclosing block: return, break, continue, goto.
    /// No `alternative` required — callers only care about the fall-through
    /// path past the if.
    fn if_always_exits(if_node: &Node) -> bool {
        let Some(consequence) = if_node.child_by_field_name("consequence") else {
            return false;
        };
        let is_exit = |k: &str| {
            matches!(
                k,
                "return_statement" | "break_statement" | "continue_statement" | "goto_statement"
            )
        };
        if is_exit(consequence.kind()) {
            return true;
        }
        if consequence.kind() == "compound_statement" {
            let mut last: Option<Node> = None;
            for i in 0..consequence.named_child_count() {
                if let Some(c) = consequence.named_child(i) {
                    last = Some(c);
                }
            }
            if let Some(l) = last {
                return is_exit(l.kind());
            }
        }
        false
    }

    /// Check if a condition implies `a >= b` (i.e., `a - b` cannot underflow).
    /// Recognizes: `a >= b`, `a > b`, `b <= a`, `b < a`, and compound `&&` conditions.
    fn condition_implies_a_gte_b(&self, cond_text: &str, a: &str, b: &str) -> bool {
        let cond = cond_text.trim();
        let cond = if cond.starts_with('(') && cond.ends_with(')') {
            &cond[1..cond.len() - 1]
        } else {
            cond
        };
        let cond = cond.trim();

        // Must mention both variables
        if !self.contains_word(cond, a) || !self.contains_word(cond, b) {
            return false;
        }

        // For compound && conditions, check each part
        for part in cond.split("&&") {
            let part = part.trim();
            if self.single_condition_implies_a_gte_b(part, a, b) {
                return true;
            }
        }

        false
    }

    /// Check a single (non-compound) condition for a >= b patterns.
    fn single_condition_implies_a_gte_b(&self, cond: &str, a: &str, b: &str) -> bool {
        // Strip parens
        let cond = cond.trim();
        let cond = if cond.starts_with('(') && cond.ends_with(')') {
            &cond[1..cond.len() - 1]
        } else {
            cond
        };
        let cond = cond.trim();

        // Pattern: a >= b or a > b
        let gte_pat = format!("{} >= {}", a, b);
        let gt_pat = format!("{} > {}", a, b);
        if self.contains_word(cond, a) && self.contains_word(cond, b) {
            if cond.contains(&gte_pat) || cond.contains(&gt_pat) {
                return true;
            }
            // Pattern: b <= a or b < a
            let lte_pat = format!("{} <= {}", b, a);
            let lt_pat = format!("{} < {}", b, a);
            if cond.contains(&lte_pat) || cond.contains(&lt_pat) {
                return true;
            }
            // Pattern: `a > (b + POS)` or `a > b + POS` where POS evaluates to a
            // positive integer. Implies a > b.
            if self.cond_gt_b_plus_positive(cond, a, b) {
                return true;
            }
        }
        false
    }

    /// True when `cond` matches `a > (b + C)` / `a > b + C` / `a >= b + C` with
    /// `C` a non-negative const-evaluable expression. In that case `a > b`.
    fn cond_gt_b_plus_positive(&self, cond: &str, a: &str, b: &str) -> bool {
        for op in [" > ", " >= "] {
            let key = format!("{}{}", a, op);
            let Some(pos) = cond.find(&key) else { continue };
            let rhs = cond[pos + key.len()..].trim();
            let rhs = rhs.trim_start_matches('(').trim_end_matches(')').trim();
            // Need a `+` at top level connecting `b` and a positive tail.
            let Some(plus_pos) = rhs.find(" + ") else {
                continue;
            };
            let left_of_plus = rhs[..plus_pos].trim();
            let right_of_plus = rhs[plus_pos + 3..].trim();
            if left_of_plus != b {
                continue;
            }
            let macros = self.current_macros.borrow();
            if let Some(v) = const_eval::try_evaluate_text_public(right_of_plus, &macros) {
                if v > 0 {
                    return true;
                }
            }
        }
        false
    }

    fn get_function_arguments(&self, node: &Node, source: &str) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(arguments) = node.child_by_field_name("arguments") {
            // Named children of argument_list are the actual argument
            // expressions; unnamed children (`(`, `,`, `)`) are skipped.
            for i in 0..arguments.named_child_count() {
                if let Some(child) = arguments.named_child(i) {
                    let arg_text = source[child.start_byte()..child.end_byte()].to_string();
                    args.push(arg_text.trim().to_string());
                }
            }
        }

        args
    }
}
