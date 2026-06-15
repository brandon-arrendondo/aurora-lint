use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::FunctionCfg;
use crate::analyze::const_eval::{self, MacroConstantMap, VarRangeMap};
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::value_range::RangeAnalysisResult;
use crate::analyze::vra_access;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::std_functions;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Int32C {
    project_macros: RefCell<MacroConstantMap>,
    current_macros: RefCell<MacroConstantMap>,
    struct_field_types: RefCell<HashMap<String, HashMap<String, String>>>,
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
}

impl Int32C {
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

        // Risky-var memo is keyed on tree-sitter node ids, which are only unique
        // within a single parse tree — reset it for each file.
        self.risky_vars_cache.borrow_mut().clear();

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
        // Skip nodes inside compile-time contexts (cannot overflow at runtime)
        if self.is_in_compile_time_context(node) {
            return;
        }

        match node.kind() {
            "binary_expression" => {
                self.check_binary_operation(node, source, violations, type_map);
            }
            "assignment_expression" => {
                self.check_assignment_operation(node, source, violations, type_map);
            }
            "unary_expression" => {
                self.check_unary_operation(node, source, violations, type_map);
            }
            "update_expression" => {
                self.check_increment_decrement(node, source, violations, type_map);
            }
            "call_expression" => {
                self.check_function_call(node, source, violations);
            }
            _ => {}
        }

        // Recursively check child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                // Scope type_map per function to avoid cross-function name collisions
                // (e.g., float X_pred in one function vs int32_t X_pred in another)
                if child.kind() == "function_definition" {
                    let fn_type_map = self.collect_variable_types(&child, source);
                    self.check_node(&child, source, violations, &fn_type_map);
                } else {
                    self.check_node(&child, source, violations, type_map);
                }
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
                self.check_negation(node, source, violations, type_map);
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

                // Skip if constant evaluation proves the result fits in the operand type's range
                let vra_bits = Self::signed_type_bits(&left_type, &right_type);
                if const_eval::expression_fits_in_signed_vra(
                    node,
                    source,
                    &self.current_macros.borrow(),
                    vra_bits,
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

                // Skip if constant evaluation proves the result fits in the operand type's range
                let vra_bits = Self::signed_type_bits(&left_type, &right_type);
                if const_eval::expression_fits_in_signed_vra(
                    node,
                    source,
                    &self.current_macros.borrow(),
                    vra_bits,
                    self.vra_var_ranges_at(node, source).as_ref(),
                ) {
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

                // Skip if constant evaluation proves the result fits in the operand type's range
                let vra_bits = Self::signed_type_bits(&left_type, &right_type);
                if const_eval::expression_fits_in_signed_vra(
                    node,
                    source,
                    &self.current_macros.borrow(),
                    vra_bits,
                    self.vra_var_ranges_at(node, source).as_ref(),
                ) {
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

                // Skip if constant evaluation proves the result fits in the operand type's range
                let vra_bits = Self::signed_type_bits(&left_type, &left_type);
                if const_eval::expression_fits_in_signed_vra(
                    node,
                    source,
                    &self.current_macros.borrow(),
                    vra_bits,
                    self.vra_var_ranges_at(node, source).as_ref(),
                ) {
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

                // Skip if constant evaluation proves the result fits in the operand type's range
                let vra_bits = Self::signed_type_bits(&left_type, &left_type);
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

                // Skip if constant evaluation proves the result fits in the operand type's range
                let vra_bits = Self::signed_type_bits(&left_type, &left_type);
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

                // Skip if constant evaluation proves the result fits in the operand type's range
                let vra_bits = Self::signed_type_bits(&left_type, &left_type);
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
                // Skip if constant evaluation proves the result fits in the operand type's range
                let vra_bits = Self::signed_type_bits(&left_type, &left_type);
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

                // Skip if VRA proves the result fits in the operand type's range
                let vra_bits = Self::signed_type_bits(&arg_type, &arg_type);
                if const_eval::expression_fits_in_signed_vra(
                    node,
                    source,
                    &self.current_macros.borrow(),
                    vra_bits,
                    self.vra_var_ranges_at(node, source).as_ref(),
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

    fn check_function_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            // Check for functions that commonly receive arithmetic expressions that might overflow
            match function_name {
                "malloc" | "calloc" | "realloc" => {
                    self.check_allocation_overflow(node, source, function_name, violations);
                }
                "memcpy" | "memmove" | "memset" => {
                    self.check_memory_function_overflow(node, source, function_name, violations);
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
                            arg_idx += 1;
                            continue;
                        }
                        drop(macros);
                        if !self.has_allocation_overflow_check(node, source) {
                            let start_point = node.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "{}() argument {} contains arithmetic that may overflow: '{}'",
                                    function_name,
                                    arg_idx + 1,
                                    arg_text
                                ),
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
        let mut type_map = HashMap::new();

        if node.kind() == "function_definition" {
            // Collect from function parameters
            if let Some(declarator) = node.child_by_field_name("declarator") {
                self.collect_params_from_declarator(&declarator, source, &mut type_map);
            }
            // Collect from local declarations in the function body
            if let Some(body) = node.child_by_field_name("body") {
                self.collect_local_declarations(&body, source, &mut type_map);
            }
        }

        // Recurse into children to find nested function_definitions
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let child_map = self.collect_variable_types(&child, source);
                type_map.extend(child_map);
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
        if node.kind() == "function_declarator" {
            if let Some(params) = node.child_by_field_name("parameters") {
                for i in 0..params.child_count() {
                    if let Some(param) = params.child(i) {
                        if param.kind() == "parameter_declaration" {
                            self.extract_type_and_name(&param, source, type_map);
                        }
                    }
                }
            }
        }
        // Recurse to find nested function_declarator (e.g. pointer declarators)
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_params_from_declarator(&child, source, type_map);
            }
        }
    }

    fn collect_local_declarations(
        &self,
        node: &Node,
        source: &str,
        type_map: &mut HashMap<String, String>,
    ) {
        if node.kind() == "declaration" {
            self.extract_type_and_name(node, source, type_map);
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_local_declarations(&child, source, type_map);
            }
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

        // Extract variable names from declarators, tracking pointer indirection
        if let Some(declarator) = node.child_by_field_name("declarator") {
            let is_pointer = declarator.kind() == "pointer_declarator";
            if let Some(name) = Self::extract_identifier_name(&declarator, source) {
                let full_type = if is_pointer {
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
                        let is_pointer = decl.kind() == "pointer_declarator";
                        if let Some(name) = Self::extract_identifier_name(&decl, source) {
                            let full_type = if is_pointer {
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

    fn infer_type(&self, node: &Node, source: &str, type_map: &HashMap<String, String>) -> String {
        let text = get_node_text(node, source);

        // Check the type map FIRST — most reliable source of type info.
        // Must come before text heuristics because variable names like "index"
        // contain "int" as a substring, causing false signed classification.
        if node.kind() == "identifier" {
            if let Some(declared_type) = type_map.get(text) {
                if self.is_unsigned_type(declared_type) {
                    return "unsigned".to_string();
                }
                // Narrow signed types are tracked distinctly so VRA checks use
                // their actual bit width. Exact-width typedefs are checked
                // before the generic contains("int") test. For plain short we
                // use the standard-guaranteed minimum width (16 bits).
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
                // char is a signed integer type (on most platforms); track it distinctly
                // so we can apply 8-bit VRA checking rather than 32-bit
                if declared_type == "char" || declared_type == "signed char" {
                    return "char".to_string();
                }
                // Non-integer types (float, double, pointers, structs) — not applicable to INT32-C
                return "not_applicable".to_string();
            }
        }

        // Look for explicit unsigned type indicators
        if text.contains("unsigned") || text.contains("size_t") || text.contains("uint") {
            return "unsigned".to_string();
        }

        // Look for unsigned literals
        if text.ends_with("u") || text.ends_with("U") {
            return "unsigned".to_string();
        }

        // Look for unsigned constants
        if text.contains("UINT_MAX") || text.contains("SIZE_MAX") {
            return "unsigned".to_string();
        }

        // Field expressions (e.g., s->count): try to resolve via struct field type database
        if node.kind() == "field_expression" {
            let sft = self.struct_field_types.borrow();
            if let Some(field_type) =
                crate::utility::cert_c::ast_utils::resolve_field_expression_type(
                    node, source, type_map, &sft,
                )
            {
                if self.is_unsigned_type(&field_type) {
                    return "unsigned".to_string();
                }
                if field_type == "int8_t" {
                    return "char".to_string();
                }
                if field_type == "int16_t" || field_type.contains("short") {
                    return "short".to_string();
                }
                if field_type.contains("int")
                    || field_type.contains("long")
                    || field_type == "signed"
                {
                    return "signed".to_string();
                }
                if field_type == "char" || field_type == "signed char" {
                    return "char".to_string();
                }
                return "not_applicable".to_string();
            }
            return "not_applicable".to_string();
        }

        // Binary expressions: propagate unsigned/not_applicable from sub-operands.
        // If any operand in the chain is unsigned, the whole expression should be
        // treated as unsigned (matching C integer promotion rules for unsigned types).
        if node.kind() == "binary_expression" {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                let lt = self.infer_type(&left, source, type_map);
                let rt = self.infer_type(&right, source, type_map);
                if lt == "unsigned" || rt == "unsigned" {
                    return "unsigned".to_string();
                }
                if lt == "not_applicable" || rt == "not_applicable" {
                    return "not_applicable".to_string();
                }
                if lt == "signed" || rt == "signed" {
                    return "signed".to_string();
                }
                // Narrow operands promote to int, but we keep the narrow-type
                // annotation so callers can use 16-bit/8-bit VRA checking
                if lt == "short" || rt == "short" {
                    return "short".to_string();
                }
                if lt == "char" || rt == "char" {
                    return "char".to_string();
                }
                return "unknown".to_string();
            }
        }

        // Look for explicit signed type indicators (only for non-identifier nodes
        // like type specifiers in casts/declarations — identifiers checked above)
        if node.kind() != "identifier" && text.contains("short") {
            return "short".to_string();
        }
        if node.kind() != "identifier"
            && (text.contains("signed") || text.contains("int") || text.contains("long"))
        {
            return "signed".to_string();
        }

        // Look for signed integer constants
        if text.contains("INT_MAX") || text.contains("INT_MIN") {
            return "signed".to_string();
        }

        // Plain numbers without unsigned suffix are typically signed
        if text.chars().all(|c| c.is_ascii_digit() || c == '-') {
            return "signed".to_string();
        }

        // Fall back to old heuristic for variable names not in the type map
        if text.chars().all(|c| c.is_ascii_alphabetic() || c == '_') {
            if let Some(declared_type) = self.find_variable_declaration(node, source, text) {
                return declared_type;
            }
        }

        // ALL_CAPS identifiers (including those with digits/underscores) are macros whose
        // type cannot be determined without macro expansion. Hardware register addresses
        // (e.g., AFE_INT_EN) look like signed integer literals to the type inference but
        // are actually pointer-width constants. Treat as not_applicable to avoid FPs.
        if !text.is_empty()
            && text
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            return "not_applicable".to_string();
        }

        // Variable names that suggest unsigned integers
        if text.starts_with("u") || text.contains("size") || text.contains("len") {
            return "unsigned".to_string();
        }

        // Variable names that suggest signed integers
        if text.starts_with("i")
            || text.contains("signed")
            || text.contains("count")
            || text.contains("index")
        {
            return "signed".to_string();
        }

        // For variables NOT in the type map, default to unknown instead of signed
        // This prevents false positives on variables whose type we can't determine
        "unknown".to_string()
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
                    let params_text = get_node_text(&params, source);
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
                let decl_text = get_node_text(&parent, source);
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
        type_str == "signed" || type_str == "int" || type_str == "char" || type_str == "short"
    }

    fn signed_type_bits(left_type: &str, right_type: &str) -> u32 {
        let bits_for = |t: &str| match t {
            "char" => 8u32,
            "short" => 16u32,
            _ => 32u32,
        };
        bits_for(left_type).min(bits_for(right_type))
    }

    fn is_unsigned_type(&self, type_str: &str) -> bool {
        type_str == "unsigned"
            || type_str == "size_t"
            || type_str.contains("uint")
            || type_str.starts_with("unsigned ")
            || type_str == "SIZE_MAX"
            || is_short_unsigned_typedef(type_str)
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
        let mut names = Vec::new();
        if let Some(left) = node.child_by_field_name("left") {
            Self::collect_identifiers(&left, source, &mut names);
        }
        if let Some(right) = node.child_by_field_name("right") {
            Self::collect_identifiers(&right, source, &mut names);
        }
        // For unary/update expressions, check argument
        if let Some(arg) = node.child_by_field_name("argument") {
            Self::collect_identifiers(&arg, source, &mut names);
        }
        names
    }

    fn collect_identifiers(node: &Node, source: &str, names: &mut Vec<String>) {
        if node.kind() == "identifier" {
            let name = get_node_text(node, source).to_string();
            if !names.contains(&name) {
                names.push(name);
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                Self::collect_identifiers(&child, source, names);
            }
        }
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
        match (ty("left"), ty("right"), ty("argument")) {
            (Some(l), Some(r), _) => Self::signed_type_bits(&l, &r),
            (Some(l), None, _) => Self::signed_type_bits(&l, &l),
            (_, _, Some(a)) => Self::signed_type_bits(&a, &a),
            _ => 32,
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

        // Compute (once per function) the set of variable names fed from a risky
        // source, memoized by the function node id.
        let func_id = func.id();
        {
            let mut cache = self.risky_vars_cache.borrow_mut();
            cache
                .entry(func_id)
                .or_insert_with(|| collect_risky_vars(&body, &summaries, source));
        }
        let cache = self.risky_vars_cache.borrow();
        let risky_vars = match cache.get(&func_id) {
            Some(s) => s,
            None => return true,
        };

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

        operands
            .iter()
            .any(|op| self.operand_is_risky(op, risky_vars, &summaries, source))
    }

    /// Classify a single operand subtree's provenance against the precomputed
    /// risky-variable set. See [`Self::has_risky_operand_provenance`].
    fn operand_is_risky(
        &self,
        op: &Node,
        risky_vars: &HashSet<String>,
        summaries: &HashMap<String, FunctionSummary>,
        source: &str,
    ) -> bool {
        match op.kind() {
            "call_expression" => match op.child_by_field_name("function") {
                Some(f) => callee_is_risky_source(&get_node_text(&f, source), summaries),
                None => false,
            },
            "identifier" => {
                let name = get_node_text(op, source);
                risky_vars.contains(name) || self.global_is_tainted(name, summaries)
            }
            "parenthesized_expression" => match op.named_child(0) {
                Some(inner) => self.operand_is_risky(&inner, risky_vars, summaries, source),
                None => false,
            },
            "cast_expression" => match op.child_by_field_name("value") {
                Some(value) => self.operand_is_risky(&value, risky_vars, summaries, source),
                None => false,
            },
            "binary_expression" => {
                op.child_by_field_name("left")
                    .is_some_and(|l| self.operand_is_risky(&l, risky_vars, summaries, source))
                    || op
                        .child_by_field_name("right")
                        .is_some_and(|r| self.operand_is_risky(&r, risky_vars, summaries, source))
            }
            "unary_expression" | "update_expression" => match op.child_by_field_name("argument") {
                Some(arg) => self.operand_is_risky(&arg, risky_vars, summaries, source),
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
    fn global_is_tainted(&self, name: &str, summaries: &HashMap<String, FunctionSummary>) -> bool {
        let writers = self.global_writers.borrow();
        match writers.get(name) {
            Some(ws) => ws.iter().any(|w| {
                matches!(summaries.get(w), Some(s) if s.has_env03_taint_source || s.returns_tainted)
            }),
            None => false,
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
                        return Self::resolve_identifier_call_name(&body, var_name, source, n);
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
                // declaration: type var = call();
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
                // assignment: var = call();
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
                // Recurse into preproc blocks and nested scopes
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
    fn is_in_bounded_for_loop(&self, node: &Node, source: &str) -> bool {
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "for_statement" {
                let for_text = get_node_text(&parent, source);
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
                        return true;
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
                let func_text = get_node_text(&parent, source);

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
                let context = get_node_text(&grandparent, source);
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
        let text = get_node_text(node, source);
        if text.contains("++") {
            "++".to_string()
        } else if text.contains("--") {
            "--".to_string()
        } else {
            "unknown".to_string()
        }
    }
}

fn is_simple_c_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// True when `callee` (any function-reference text) names a source of
/// untrusted or full-range values: a full-range integer parser
/// (`atoi`/`strtol`/`rand`/`RAND32`/`ntohl`), a standard environment/IO taint
/// source (`scanf`/`recv`/`fgets`/`getenv`/...), or a project-local function
/// whose prescan summary carries taint (`has_env03_taint_source` directly or
/// `returns_tainted` transitively). Used by the INT32-C provenance gate.
fn callee_is_risky_source(callee: &str, summaries: &HashMap<String, FunctionSummary>) -> bool {
    let ident = callee
        .rsplit(|c: char| !c.is_alphanumeric() && c != '_')
        .next()
        .unwrap_or(callee)
        .trim();
    if std_functions::is_full_range_return_function(ident) {
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
/// Memoized per function by the caller, so this O(body) walk runs once per
/// function rather than once per arithmetic operand.
fn collect_risky_vars(
    body: &Node,
    summaries: &HashMap<String, FunctionSummary>,
    source: &str,
) -> HashSet<String> {
    let mut set = HashSet::new();
    collect_risky_vars_walk(body, summaries, source, &mut set);
    set
}

fn collect_risky_vars_walk(
    node: &Node,
    summaries: &HashMap<String, FunctionSummary>,
    source: &str,
    set: &mut HashSet<String>,
) {
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

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_risky_vars_walk(&child, summaries, source, set);
        }
    }
}

/// Insert every identifier appearing in `args` into `set`.
fn collect_arg_identifiers(args: &Node, source: &str, set: &mut HashSet<String>) {
    if args.kind() == "identifier" {
        set.insert(get_node_text(args, source).trim().to_string());
        return;
    }
    for i in 0..args.child_count() {
        if let Some(child) = args.child(i) {
            collect_arg_identifiers(&child, source, set);
        }
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

/// Recognizes common short unsigned typedef names: u8, u16, u32, u64, u128.
/// These are MCU/embedded typedefs not caught by the "uint" substring check.
fn is_short_unsigned_typedef(s: &str) -> bool {
    matches!(s, "u8" | "u16" | "u32" | "u64" | "u128")
}
