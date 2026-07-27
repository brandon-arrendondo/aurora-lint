use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::FunctionCfg;
use crate::analyze::const_eval::{self, MacroConstantMap, VarRangeMap};
use crate::analyze::context::ProjectContext;
use crate::analyze::value_range::{self, RangeAnalysisResult};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Int34C {
    project_macros: RefCell<MacroConstantMap>,
    current_macros: RefCell<MacroConstantMap>,
    /// Per-function CFGs
    function_cfgs: RefCell<HashMap<usize, FunctionCfg>>,
    /// Per-function VRA results
    vra_results: RefCell<HashMap<usize, RangeAnalysisResult>>,
}

impl Int34C {
    pub fn new() -> Self {
        Self {
            project_macros: RefCell::new(MacroConstantMap::new()),
            current_macros: RefCell::new(MacroConstantMap::new()),
            function_cfgs: RefCell::new(HashMap::new()),
            vra_results: RefCell::new(HashMap::new()),
        }
    }
}

impl CertRule for Int34C {
    fn rule_id(&self) -> &'static str {
        "INT34-C"
    }

    fn description(&self) -> &'static str {
        "Do not shift an expression by a negative number of bits or by greater than or equal to the number of bits that exist in the operand"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "INT34-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_macros.borrow_mut() = context.macro_constants.clone();
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

        // Merge project-level macros with per-file macros
        let mut macros = self.project_macros.borrow().clone();
        macros.extend(const_eval::collect_macro_constants(node, source));
        *self.current_macros.borrow_mut() = macros;

        self.check_recursive(node, source, &mut violations);
        violations
    }
}

impl Int34C {
    fn check_recursive(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for binary_node in query::find_descendants_of_kind(*node, "binary_expression") {
            if let Some(operator) = ast_utils::get_binary_operator(&binary_node, source) {
                if operator == "<<" || operator == ">>" {
                    self.check_shift_operation(&binary_node, source, operator, violations);
                }
            }
        }
    }

    /// Check if a shift operation is safe
    fn check_shift_operation(
        &self,
        node: &Node,
        source: &str,
        _operator: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let left = node.child_by_field_name("left");
        let right = node.child_by_field_name("right");

        if let (Some(left_node), Some(right_node)) = (left, right) {
            let right_text = ast_utils::get_node_text(&right_node, source);
            let left_text = ast_utils::get_node_text(&left_node, source);

            // If the shift amount is a non-negative integer literal the rule is
            // trivially satisfied: negative-shift cannot happen, and width-overflow
            // is a compiler-visible property of the constant (compilers warn on
            // e.g. `x >> 64`).  INT34-C is only meaningful for *variable* shift
            // amounts whose range cannot be determined at compile time.
            if self.is_non_negative_integer_literal(&right_node, source) {
                return;
            }

            // If the shift amount contains a modulo operation with a small
            // constant (e.g. `(pos + bi) % 8u`), the result is always bounded
            // to [0, modulus-1] — guaranteed within type width for any standard
            // integer type.
            if self.shift_amount_bounded_by_modulo(&right_node, source) {
                return;
            }

            // Try CFG-based VRA first (more precise)
            if let Some(range) = self.eval_shift_range_via_vra(node, &right_node, source) {
                // A compile-time constant shift (min == max, non-negative) is
                // equivalent to a numeric literal — the compiler validates it and
                // INT34-C adds nothing.  Variable shifts bounded to [0, 31] are
                // also safe for 32-bit operands.
                if range.min >= 0 && (range.min == range.max || range.max < 32) {
                    return;
                }
            }

            // Fallback: syntactic const_eval range analysis on the shift amount.
            {
                let macros = self.current_macros.borrow();
                let mut var_ranges = const_eval::extract_loop_var_ranges(node, source, &macros);
                Self::extract_if_condition_ranges(node, source, &macros, &mut var_ranges);

                if let Some(range) =
                    const_eval::try_evaluate_range(&right_node, source, &macros, &var_ranges)
                {
                    // Same logic: single-value constants and 32-bit-bounded variables are safe.
                    if range.min >= 0 && (range.min == range.max || range.max < 32) {
                        return;
                    }
                }
            }

            // Check if this is an unsigned type operation. Unsigned shifts
            // avoid the signed-overflow hazard that makes `<<` on signed
            // types especially dangerous, but the shift COUNT itself being
            // negative or >= the operand's bit width is undefined behavior
            // regardless of direction or signedness (C11 6.5.7p3) --
            // verified against CERT's own "Compliant Solution (Right
            // Shift)" example, which adds the same PRECISION() bound check
            // to an unsigned `>>`. So both operators require validation
            // for both signed and unsigned operands.
            if self.is_likely_unsigned(left_text, &left_node, source) {
                if !self.is_shift_amount_validated(node, &right_node, source) {
                    self.report_violation(
                        node,
                        left_text.to_string(),
                        right_text.to_string(),
                        source,
                        violations,
                    );
                }
            } else {
                // For signed types or unknown types, require validation for both left and right shifts
                if !self.is_shift_amount_validated(node, &right_node, source) {
                    self.report_violation(
                        node,
                        left_text.to_string(),
                        right_text.to_string(),
                        source,
                        violations,
                    );
                }
            }
        }
    }

    fn report_violation(
        &self,
        node: &Node,
        _left_text: String,
        right_text: String,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let operation = ast_utils::get_node_text(node, source);

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message: format!(
                "Shift operation '{}' by '{}' without validating shift amount is non-negative and within type width",
                operation, right_text
            ),
            file_path: String::new(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            suggestion: Some(format!(
                "Check that '{}' is >= 0 and < the bit width of the operand before shifting",
                right_text
            )),
            ..Default::default()
        });
    }

    /// Returns true if the shift amount expression is bounded by a modulo operation
    /// with a constant divisor that's within type width (e.g., `expr % 8u` gives 0-7).
    fn shift_amount_bounded_by_modulo(&self, node: &Node, source: &str) -> bool {
        // Direct modulo: `expr % N`
        if node.kind() == "binary_expression" {
            if let Some(op) = ast_utils::get_binary_operator(node, source) {
                if op == "%" {
                    if let Some(right) = node.child_by_field_name("right") {
                        if self.is_non_negative_integer_literal(&right, source) {
                            let text = ast_utils::get_node_text(&right, source)
                                .trim()
                                .to_ascii_lowercase();
                            let stripped = text.trim_end_matches(['u', 'l']);
                            if let Ok(modulus) = stripped.parse::<u64>() {
                                // modulus <= 64 means result is 0..modulus-1, within any type width
                                return modulus > 0 && modulus <= 64;
                            }
                        }
                    }
                }
            }
        }
        // Parenthesized: `(expr % N)`
        if node.kind() == "parenthesized_expression" {
            if let Some(inner) = node.child(1) {
                return self.shift_amount_bounded_by_modulo(&inner, source);
            }
        }
        false
    }

    /// Returns true if the node is a non-negative integer literal
    /// (decimal, hex, octal, or binary), including those with suffix letters
    /// such as `8u`, `16UL`, `0x1FUL`.
    fn is_non_negative_integer_literal(&self, node: &Node, source: &str) -> bool {
        // tree-sitter-c uses "number_literal" for all numeric constants.
        if node.kind() != "number_literal" {
            return false;
        }
        let text = ast_utils::get_node_text(node, source)
            .trim()
            .to_ascii_lowercase();
        // Strip common integer suffixes (u, l, ul, ull, lu, llu)
        let stripped = text.trim_end_matches(['u', 'l']);
        // Must be parseable as a non-negative integer (decimal, hex, octal)
        if let Some(hex) = stripped.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).is_ok()
        } else if let Some(bin) = stripped.strip_prefix("0b") {
            u64::from_str_radix(bin, 2).is_ok()
        } else if stripped.starts_with('0') && stripped.len() > 1 {
            u64::from_str_radix(&stripped[1..], 8).is_ok()
        } else {
            stripped.parse::<u64>().is_ok()
        }
    }

    /// Check if the operand is likely an unsigned type
    fn is_likely_unsigned(&self, var_name: &str, node: &Node, source: &str) -> bool {
        // Check common naming conventions for unsigned variables
        if var_name.starts_with("ui_")
            || var_name.starts_with("u_")
            || var_name.starts_with("unsigned_")
        {
            return true;
        }

        if let Some(func) = ast_utils::find_containing_function(node) {
            // Check function parameters via function_declarator → parameter_list
            if let Some(param_list) = self.find_parameter_list(&func) {
                for i in 0..param_list.child_count() {
                    if let Some(param) = param_list.child(i) {
                        if param.kind() == "parameter_declaration"
                            && self.decl_has_unsigned_var(&param, var_name, source)
                        {
                            return true;
                        }
                    }
                }
            }
            // Check local variable declarations in function body
            if let Some(body) = func.child_by_field_name("body") {
                if self.body_has_unsigned_var(&body, var_name, source) {
                    return true;
                }
            }
        }

        false
    }

    /// Find the parameter_list node within a function_definition.
    /// Traverses: function_definition → function_declarator → parameter_list
    fn find_parameter_list<'a>(&self, func: &'a Node) -> Option<Node<'a>> {
        for i in 0..func.child_count() {
            if let Some(child) = func.child(i) {
                if child.kind() == "function_declarator" {
                    for j in 0..child.child_count() {
                        if let Some(grandchild) = child.child(j) {
                            if grandchild.kind() == "parameter_list" {
                                return Some(grandchild);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if a declaration node declares `var_name` with an unsigned type.
    /// Works for both parameter_declaration and declaration nodes.
    fn decl_has_unsigned_var(&self, decl: &Node, var_name: &str, source: &str) -> bool {
        let mut has_unsigned = false;
        let mut declares_var = false;

        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                match child.kind() {
                    "sized_type_specifier" => {
                        let text = ast_utils::get_node_text(&child, source);
                        if text.contains("unsigned") {
                            has_unsigned = true;
                        }
                    }
                    "identifier" if ast_utils::get_node_text(&child, source) == var_name => {
                        declares_var = true;
                    }
                    "pointer_declarator" | "array_declarator" | "init_declarator"
                        if self.declarator_contains_name(&child, var_name, source) =>
                    {
                        declares_var = true;
                    }
                    _ => {}
                }
            }
        }

        has_unsigned && declares_var
    }

    /// Recursively check if a declarator subtree contains an identifier matching var_name.
    fn declarator_contains_name(&self, node: &Node, var_name: &str, source: &str) -> bool {
        if node.kind() == "identifier" {
            return ast_utils::get_node_text(node, source) == var_name;
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if self.declarator_contains_name(&child, var_name, source) {
                    return true;
                }
            }
        }
        false
    }

    /// Walk a compound_statement looking for local declarations of var_name with unsigned type.
    fn body_has_unsigned_var(&self, body: &Node, var_name: &str, source: &str) -> bool {
        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                if child.kind() == "declaration"
                    && self.decl_has_unsigned_var(&child, var_name, source)
                {
                    return true;
                }
            }
        }
        false
    }

    /// Check if shift amount has been validated
    fn is_shift_amount_validated(
        &self,
        shift_node: &Node,
        shift_amount: &Node,
        source: &str,
    ) -> bool {
        let shift_var = ast_utils::get_node_text(shift_amount, source);

        // Find the containing function
        if let Some(func) = ast_utils::find_containing_function(shift_node) {
            if let Some(body) = func.child_by_field_name("body") {
                // Check if there's validation before the shift
                if self.has_validation_check(&body, shift_var, source, shift_node) {
                    return true;
                }
            }
        }

        // Check parent if/while/for statements
        let mut current = shift_node.parent();
        while let Some(node) = current {
            match node.kind() {
                "if_statement" => {
                    if let Some(condition) = node.child_by_field_name("condition") {
                        if self.checks_shift_bounds(&condition, shift_var, source) {
                            if self.is_in_safe_branch(&node, shift_node) {
                                return true;
                            }
                        }
                    }
                }
                "while_statement" | "for_statement" | "do_statement" => {
                    // If the shift amount expression contains an identifier
                    // bounded by this loop condition to a small value, it's safe.
                    if let Some(condition) = node.child_by_field_name("condition") {
                        if self.loop_bounds_shift_amount(&condition, shift_amount, source) {
                            return true;
                        }
                    }
                }
                _ => {}
            }
            current = node.parent();
        }

        false
    }

    /// Check if a loop condition bounds the shift amount to a safe range.
    /// Extracts identifiers from the shift amount and checks if the loop
    /// condition constrains them to < 32.
    fn loop_bounds_shift_amount(
        &self,
        condition: &Node,
        shift_amount: &Node,
        source: &str,
    ) -> bool {
        // Collect identifiers from the shift amount expression
        let mut shift_vars = Vec::new();
        Self::collect_identifiers_from(shift_amount, source, &mut shift_vars);
        if shift_vars.is_empty() {
            return false;
        }

        // Unwrap parenthesized_expression
        let cond = if condition.kind() == "parenthesized_expression" {
            match condition.child(1) {
                Some(c) => c,
                None => return false,
            }
        } else {
            *condition
        };

        // Check if any shift variable appears in a < or <= comparison with a small bound
        if self.condition_bounds_var_small(&cond, &shift_vars, source) {
            return true;
        }

        // Check for (expr >> var) != 0 pattern — this implicitly bounds var
        // to less than the bit width of expr (e.g., uint32_t → < 32).
        if self.condition_is_shift_to_zero_check(&cond, &shift_vars, source) {
            return true;
        }

        false
    }

    fn collect_identifiers_from(node: &Node, source: &str, names: &mut Vec<String>) {
        for id_node in query::find_descendants_of_kind(*node, "identifier") {
            let name = ast_utils::get_node_text(&id_node, source).to_string();
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }

    /// Check if a condition bounds any of the given variables to less than 32.
    fn condition_bounds_var_small(&self, cond: &Node, var_names: &[String], source: &str) -> bool {
        if cond.kind() != "binary_expression" {
            return false;
        }
        let op = ast_utils::get_binary_operator(cond, source).unwrap_or_default();

        // Handle && conditions
        if op == "&&" {
            if let Some(left) = cond.child_by_field_name("left") {
                if self.condition_bounds_var_small(&left, var_names, source) {
                    return true;
                }
            }
            if let Some(right) = cond.child_by_field_name("right") {
                if self.condition_bounds_var_small(&right, var_names, source) {
                    return true;
                }
            }
            return false;
        }

        // Check var < N or var <= N patterns
        let (left, right) = match (
            cond.child_by_field_name("left"),
            cond.child_by_field_name("right"),
        ) {
            (Some(l), Some(r)) => (l, r),
            _ => return false,
        };
        let left_text = ast_utils::get_node_text(&left, source);
        let right_text = ast_utils::get_node_text(&right, source);

        // var < BOUND or var <= BOUND
        if (op == "<" || op == "<=") && var_names.iter().any(|v| v == left_text) {
            // Try to parse the bound as a small number
            if let Ok(bound) = right_text.trim().parse::<i64>() {
                return bound <= 32;
            }
            // Try to resolve macro
            let macros = self.current_macros.borrow();
            if let Some(val) = const_eval::try_evaluate_expr(&right, source, &macros) {
                return val <= 32;
            }
        }

        // BOUND > var or BOUND >= var
        if (op == ">" || op == ">=") && var_names.iter().any(|v| v == right_text) {
            if let Ok(bound) = left_text.trim().parse::<i64>() {
                return bound <= 32;
            }
            let macros = self.current_macros.borrow();
            if let Some(val) = const_eval::try_evaluate_expr(&left, source, &macros) {
                return val <= 32;
            }
        }

        false
    }

    /// Recognize `(expr >> var) != 0` as implicitly bounding `var`.
    /// When a while-loop condition is `(mask >> bi) != 0u`, `bi` is bounded
    /// to less than the bit width of mask (at most 31 for uint32_t).
    fn condition_is_shift_to_zero_check(
        &self,
        cond: &Node,
        var_names: &[String],
        source: &str,
    ) -> bool {
        if cond.kind() != "binary_expression" {
            return false;
        }
        let op = ast_utils::get_binary_operator(cond, source).unwrap_or_default();
        if op != "!=" && op != "==" {
            return false;
        }

        let (left, right) = match (
            cond.child_by_field_name("left"),
            cond.child_by_field_name("right"),
        ) {
            (Some(l), Some(r)) => (l, r),
            _ => return false,
        };

        // One side should be 0/0u, the other should be (expr >> var)
        let (shift_side, zero_side) = if self.is_zero_literal(&right, source) {
            (left, right)
        } else if self.is_zero_literal(&left, source) {
            (right, left)
        } else {
            return false;
        };
        let _ = zero_side; // used only for selection above

        // shift_side should be a right-shift containing one of our variables
        let shift_expr = if shift_side.kind() == "parenthesized_expression" {
            shift_side.named_child(0).unwrap_or(shift_side)
        } else {
            shift_side
        };

        if shift_expr.kind() == "binary_expression" {
            if let Some(shift_op) = ast_utils::get_binary_operator(&shift_expr, source) {
                if shift_op == ">>" {
                    if let Some(rhs) = shift_expr.child_by_field_name("right") {
                        let rhs_text = ast_utils::get_node_text(&rhs, source);
                        if var_names.iter().any(|v| v == rhs_text) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    fn is_zero_literal(&self, node: &Node, source: &str) -> bool {
        let text = ast_utils::get_node_text(node, source).trim().to_string();
        text == "0" || text == "0u" || text == "0U" || text == "0L" || text == "0UL"
    }

    /// Check if there's a validation check in the scope before the shift
    fn has_validation_check(
        &self,
        scope: &Node,
        var_name: &str,
        source: &str,
        shift_node: &Node,
    ) -> bool {
        let shift_line = shift_node.start_position().row;

        for i in 0..scope.named_child_count() {
            if let Some(child) = scope.named_child(i) {
                let child_line = child.start_position().row;

                // Only check statements before the shift
                if child_line >= shift_line {
                    break;
                }

                if child.kind() == "if_statement" {
                    if let Some(condition) = child.child_by_field_name("condition") {
                        if self.checks_shift_bounds(&condition, var_name, source) {
                            // Check if the consequence has return/exit
                            if let Some(consequence) = child.child_by_field_name("consequence") {
                                if Self::has_return_or_error_handling(&consequence, source) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Check if a condition validates shift bounds
    fn checks_shift_bounds(&self, condition: &Node, var_name: &str, source: &str) -> bool {
        let condition_text = ast_utils::get_node_text(condition, source);

        // Look for patterns like:
        // - var < 0
        // - var < PRECISION(...)
        // - var >= PRECISION(...)
        // - var >= 32
        // - var < 32
        // - var < sizeof(type) * CHAR_BIT

        // Check for negative validation
        let has_negative_check = condition_text.contains(&format!("{} < 0", var_name))
            || condition_text.contains(&format!("0 > {}", var_name))
            || condition_text.contains(&format!("{} >= 0", var_name))
            || condition_text.contains(&format!("0 <= {}", var_name));

        // Check for width/precision validation
        let has_width_check = condition_text.contains(&format!("{} <", var_name))
            || condition_text.contains(&format!("{} >=", var_name))
            || condition_text.contains("PRECISION")
            || condition_text.contains("CHAR_BIT")
            || condition_text.contains("_MAX");

        // For thorough validation, we need both checks (or a combined check)
        // But we'll accept either for now to avoid false positives
        if has_negative_check || has_width_check {
            return true;
        }

        // Also check child binary expressions more carefully
        for i in 0..condition.child_count() {
            if let Some(child) = condition.child(i) {
                if child.kind() == "binary_expression" {
                    if let Some(operator) = ast_utils::get_binary_operator(&child, source) {
                        if operator == "<"
                            || operator == ">"
                            || operator == "<="
                            || operator == ">="
                        {
                            let left = child.child_by_field_name("left");
                            let right = child.child_by_field_name("right");

                            if let (Some(l), Some(r)) = (left, right) {
                                let left_text = ast_utils::get_node_text(&l, source);
                                let right_text = ast_utils::get_node_text(&r, source);

                                // Check if this compares our variable with bounds
                                if left_text == var_name || right_text == var_name {
                                    // Check for width-related constants or expressions
                                    if right_text.contains("PRECISION")
                                        || right_text.contains("CHAR_BIT")
                                        || right_text.contains("MAX")
                                        || left_text.contains("PRECISION")
                                        || left_text.contains("CHAR_BIT")
                                        || left_text.contains("MAX")
                                        || right_text == "0"
                                        || left_text == "0"
                                    {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Check if branch contains return or error handling
    fn has_return_or_error_handling(node: &Node, source: &str) -> bool {
        let text = ast_utils::get_node_text(node, source);

        if text.contains("return") || text.contains("error") || text.contains("exit") {
            return true;
        }

        // Check for return/exit statements in any child subtree
        let mut cursor = node.walk();
        let children: Vec<Node> = node.children(&mut cursor).collect();
        children.iter().any(|child| {
            query::find_first_descendant(*child, |n| {
                matches!(
                    n.kind(),
                    "return_statement" | "break_statement" | "continue_statement"
                )
            })
            .is_some()
        })
    }

    /// Check if shift operation is in a safe branch
    fn is_in_safe_branch(&self, if_node: &Node, shift_node: &Node) -> bool {
        // Check if shift_node is in the consequence or alternative
        if let Some(consequence) = if_node.child_by_field_name("consequence") {
            if Self::is_descendant(&consequence, shift_node) {
                return true;
            }
        }

        if let Some(alternative) = if_node.child_by_field_name("alternative") {
            if Self::is_descendant(&alternative, shift_node) {
                return true;
            }
        }

        false
    }

    /// Walk up to enclosing if_statement ancestors and extract variable
    /// bounds from their conditions. Only applies when the node is inside
    /// the consequence (then-branch) of the if.
    fn extract_if_condition_ranges(
        node: &Node,
        source: &str,
        macros: &MacroConstantMap,
        ranges: &mut VarRangeMap,
    ) {
        let mut current = node.parent();
        while let Some(ancestor) = current {
            if ancestor.kind() == "if_statement" {
                // Only apply bounds if node is in the consequence (then-branch)
                if let Some(consequence) = ancestor.child_by_field_name("consequence") {
                    if node.start_byte() >= consequence.start_byte()
                        && node.end_byte() <= consequence.end_byte()
                    {
                        if let Some(condition) = ancestor.child_by_field_name("condition") {
                            let cond = if condition.kind() == "parenthesized_expression" {
                                condition.child(1)
                            } else {
                                Some(condition)
                            };
                            if let Some(cond) = cond {
                                Self::extract_comparison_bounds(&cond, source, macros, ranges);
                            }
                        }
                    }
                }
            }
            current = ancestor.parent();
        }
    }

    /// Extract variable bounds from comparison expressions.
    /// Handles <, <=, >, >=, != operators and compound && conditions.
    fn extract_comparison_bounds(
        node: &Node,
        source: &str,
        macros: &MacroConstantMap,
        ranges: &mut VarRangeMap,
    ) {
        if node.kind() != "binary_expression" {
            return;
        }
        let op = match ast_utils::get_binary_operator(node, source) {
            Some(o) => o,
            None => return,
        };

        // Handle compound && conditions
        if op == "&&" {
            if let Some(left) = node.child_by_field_name("left") {
                Self::extract_comparison_bounds(&left, source, macros, ranges);
            }
            if let Some(right) = node.child_by_field_name("right") {
                Self::extract_comparison_bounds(&right, source, macros, ranges);
            }
            return;
        }

        let (left, right) = match (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            (Some(l), Some(r)) => (l, r),
            _ => return,
        };

        match op {
            "<" => {
                // left < right → left ∈ [_, right-1]
                if left.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&right, source, macros) {
                        let name = ast_utils::get_node_text(&left, source).to_string();
                        let entry = ranges
                            .entry(name)
                            .or_insert(const_eval::ValueRange::new(i64::MIN, i64::MAX));
                        entry.max = entry.max.min(bound - 1);
                    }
                }
                // left < right → right ∈ [left+1, _]
                if right.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&left, source, macros) {
                        let name = ast_utils::get_node_text(&right, source).to_string();
                        let entry = ranges
                            .entry(name)
                            .or_insert(const_eval::ValueRange::new(i64::MIN, i64::MAX));
                        entry.min = entry.min.max(bound + 1);
                    }
                }
            }
            "<=" => {
                if left.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&right, source, macros) {
                        let name = ast_utils::get_node_text(&left, source).to_string();
                        let entry = ranges
                            .entry(name)
                            .or_insert(const_eval::ValueRange::new(i64::MIN, i64::MAX));
                        entry.max = entry.max.min(bound);
                    }
                }
                if right.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&left, source, macros) {
                        let name = ast_utils::get_node_text(&right, source).to_string();
                        let entry = ranges
                            .entry(name)
                            .or_insert(const_eval::ValueRange::new(i64::MIN, i64::MAX));
                        entry.min = entry.min.max(bound);
                    }
                }
            }
            ">" => {
                // left > right → left ∈ [right+1, _]
                if left.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&right, source, macros) {
                        let name = ast_utils::get_node_text(&left, source).to_string();
                        let entry = ranges
                            .entry(name)
                            .or_insert(const_eval::ValueRange::new(i64::MIN, i64::MAX));
                        entry.min = entry.min.max(bound + 1);
                    }
                }
                if right.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&left, source, macros) {
                        let name = ast_utils::get_node_text(&right, source).to_string();
                        let entry = ranges
                            .entry(name)
                            .or_insert(const_eval::ValueRange::new(i64::MIN, i64::MAX));
                        entry.max = entry.max.min(bound - 1);
                    }
                }
            }
            ">=" => {
                if left.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&right, source, macros) {
                        let name = ast_utils::get_node_text(&left, source).to_string();
                        let entry = ranges
                            .entry(name)
                            .or_insert(const_eval::ValueRange::new(i64::MIN, i64::MAX));
                        entry.min = entry.min.max(bound);
                    }
                }
                if right.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&left, source, macros) {
                        let name = ast_utils::get_node_text(&right, source).to_string();
                        let entry = ranges
                            .entry(name)
                            .or_insert(const_eval::ValueRange::new(i64::MIN, i64::MAX));
                        entry.max = entry.max.min(bound);
                    }
                }
            }
            "!=" => {
                // x != 0 doesn't give a tight range for shifts, skip
            }
            _ => {}
        }
    }

    /// Check if target is a descendant of node
    fn is_descendant(node: &Node, target: &Node) -> bool {
        query::find_first_descendant(*node, |n| n.id() == target.id()).is_some()
    }

    /// Evaluate the shift amount's range using CFG-based VRA.
    fn eval_shift_range_via_vra(
        &self,
        shift_node: &Node,
        right_node: &Node,
        source: &str,
    ) -> Option<const_eval::ValueRange> {
        let vra_results = self.vra_results.borrow();
        let cfgs = self.function_cfgs.borrow();
        let macros = self.current_macros.borrow();

        if vra_results.is_empty() || cfgs.is_empty() {
            return None;
        }

        let func = ast_utils::find_containing_function(shift_node)?;
        let start_byte = func.start_byte();
        let cfg = cfgs.get(&start_byte)?;
        let vra = vra_results.get(&start_byte)?;
        let body = func.child_by_field_name("body")?;

        value_range::eval_expr_range_at(vra, cfg, &body, source, &macros, right_node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_c_code(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&crate::parser::c_language())
            .expect("Error loading C grammar");
        parser.parse(source, None).expect("Error parsing C code")
    }

    #[test]
    fn test_unchecked_shift() {
        let code = r#"
void func(unsigned int a, unsigned int b) {
    unsigned int result = a << b;
}
"#;
        let tree = parse_c_code(code);
        let rule = Int34C::new();
        let violations = rule.check(&tree.root_node(), code);
        assert!(!violations.is_empty(), "Should detect unchecked shift");
    }

    #[test]
    fn test_validated_shift() {
        let code = r#"
#include <limits.h>
void func(unsigned int a, unsigned int b) {
    unsigned int result = 0;
    if (b >= 32) {
        /* Handle error */
    } else {
        result = a << b;
    }
}
"#;
        let tree = parse_c_code(code);
        let rule = Int34C::new();
        let violations = rule.check(&tree.root_node(), code);
        assert!(
            violations.is_empty(),
            "Should not flag validated shift: {:?}",
            violations
        );
    }
}
