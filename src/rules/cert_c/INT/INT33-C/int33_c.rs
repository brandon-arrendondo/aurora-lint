use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::FunctionCfg;
use crate::analyze::const_eval::{self, MacroConstantMap, ValueRange, VarRangeMap};
use crate::analyze::context::ProjectContext;
use crate::analyze::value_range::{self, RangeAnalysisResult};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Int33C {
    project_macros: RefCell<MacroConstantMap>,
    /// Cached per-file macro constants (set once per check() call, avoids re-collecting per division node)
    file_macros: RefCell<MacroConstantMap>,
    /// Per-function CFGs (set by set_function_cfgs)
    function_cfgs: RefCell<HashMap<usize, FunctionCfg>>,
    /// Per-function VRA results (set by set_vra_results)
    vra_results: RefCell<HashMap<usize, RangeAnalysisResult>>,
}

impl Int33C {
    pub fn new() -> Self {
        Self {
            project_macros: RefCell::new(MacroConstantMap::new()),
            file_macros: RefCell::new(MacroConstantMap::new()),
            function_cfgs: RefCell::new(HashMap::new()),
            vra_results: RefCell::new(HashMap::new()),
        }
    }
}

/// Information about macros that perform division
#[allow(dead_code)]
struct DivisionMacro {
    /// Name of the macro
    name: String,
    /// Index of the divisor parameter (0-based)
    divisor_param_index: usize,
}

impl CertRule for Int33C {
    fn rule_id(&self) -> &'static str {
        "INT33-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that division and remainder operations do not result in divide-by-zero errors"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "INT33-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_macros.borrow_mut() = context.macro_constants.clone();
    }

    fn set_function_cfgs(&self, cfgs: &HashMap<usize, FunctionCfg>) {
        *self.function_cfgs.borrow_mut() = cfgs.clone();
    }

    fn set_vra_results(&self, results: &HashMap<usize, RangeAnalysisResult>) {
        // RangeAnalysisResult is not Clone, so rebuild from reference
        // We store a shared reference via a separate RefCell
        // Actually, we need to store the results. Let's use a different approach:
        // store the raw data we need.
        let mut stored = HashMap::new();
        for (&key, result) in results {
            stored.insert(
                key,
                RangeAnalysisResult {
                    block_entry_ranges: result.block_entry_ranges.clone(),
                    block_exit_ranges: result.block_exit_ranges.clone(),
                    return_ranges: result.return_ranges.clone(),
                },
            );
        }
        *self.vra_results.borrow_mut() = stored;
    }

    fn needs_vra(&self) -> bool {
        true
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Cache per-file macro constants once (avoid re-collecting per division node)
        {
            let project = self.project_macros.borrow();
            let mut cached = const_eval::collect_macro_constants(node, source);
            cached.extend(project.iter().map(|(k, v)| (k.clone(), *v)));
            *self.file_macros.borrow_mut() = cached;
        }

        // First pass: find division macros and zero-initialized variables
        let division_macros = self.find_division_macros(source);
        let zero_vars = self.find_zero_initialized_vars(node, source);

        // Check for division or modulo operations
        self.check_node(node, source, &mut violations, &division_macros, &zero_vars);

        violations
    }
}

impl Int33C {
    /// Find macros that contain division operations
    fn find_division_macros(&self, source: &str) -> HashMap<String, DivisionMacro> {
        let mut macros = HashMap::new();

        // Parse #define directives that contain division
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("#define") {
                // Parse: #define NAME(params) body
                // Look for division in the body
                if (trimmed.contains(" / ") || trimmed.contains(")/") || trimmed.contains("/("))
                    && trimmed.contains('(')
                {
                    // Extract macro name and parameters
                    if let Some(name_start) = trimmed.strip_prefix("#define") {
                        let name_part = name_start.trim();
                        if let Some(paren_pos) = name_part.find('(') {
                            let macro_name = name_part[..paren_pos].trim().to_string();

                            // Find which parameter is the divisor
                            // Look for pattern like (a) / (b) - divisor is typically the second
                            if let Some(params_end) = name_part.find(')') {
                                let params = &name_part[paren_pos + 1..params_end];
                                let param_list: Vec<&str> =
                                    params.split(',').map(|s| s.trim()).collect();

                                // The divisor is typically the second parameter in binary division
                                if param_list.len() >= 2 {
                                    macros.insert(
                                        macro_name.clone(),
                                        DivisionMacro {
                                            name: macro_name,
                                            divisor_param_index: 1, // Second parameter
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        macros
    }

    /// Find variables initialized to zero
    fn find_zero_initialized_vars(&self, node: &Node, source: &str) -> HashSet<String> {
        let mut zero_vars = HashSet::new();
        self.collect_zero_vars(node, source, &mut zero_vars);
        zero_vars
    }

    fn collect_zero_vars(&self, node: &Node, source: &str, zero_vars: &mut HashSet<String>) {
        if node.kind() == "declaration" || node.kind() == "init_declarator" {
            // Look for pattern: type var = 0
            let decl_text = ast_utils::get_node_text(node, source);
            if decl_text.contains("= 0") || decl_text.ends_with("= 0;") {
                // Extract variable name
                if let Some(name) = self.extract_declared_var_name(node, source) {
                    zero_vars.insert(name);
                }
            }
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_zero_vars(&child, source, zero_vars);
            }
        }
    }

    fn extract_declared_var_name(&self, node: &Node, source: &str) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "init_declarator" {
                    // Look for identifier in init_declarator
                    for j in 0..child.child_count() {
                        if let Some(grandchild) = child.child(j) {
                            if grandchild.kind() == "identifier" {
                                return Some(
                                    ast_utils::get_node_text(&grandchild, source).to_string(),
                                );
                            }
                        }
                    }
                } else if child.kind() == "identifier" {
                    return Some(ast_utils::get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }

    /// Main check function that processes nodes
    fn check_node(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        division_macros: &HashMap<String, DivisionMacro>,
        zero_vars: &HashSet<String>,
    ) {
        // Check for division or modulo operations
        if node.kind() == "binary_expression" {
            if let Some(operator) = ast_utils::get_binary_operator(node, source) {
                if operator == "/" || operator == "%" {
                    self.check_division_safety(node, source, violations);
                }
            }
        }

        // Check for compound assignment operators
        if node.kind() == "assignment_expression" {
            if let Some(right) = node.child_by_field_name("right") {
                let right_text = ast_utils::get_node_text(&right, source);
                // Check for /= or %=
                if !right_text.starts_with("=") {
                    // Check the operator itself
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() == "/=" || child.kind() == "%=" {
                                self.check_compound_assignment_safety(node, source, violations);
                                break;
                            }
                            let text = ast_utils::get_node_text(&child, source);
                            if text == "/=" || text == "%=" {
                                self.check_compound_assignment_safety(node, source, violations);
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Check for calls to division macros
        if node.kind() == "call_expression" {
            self.check_macro_call(node, source, violations, division_macros, zero_vars);
        }

        // Recursively check child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_node(&child, source, violations, division_macros, zero_vars);
            }
        }
    }

    /// Check if a macro call might cause division by zero
    fn check_macro_call(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        division_macros: &HashMap<String, DivisionMacro>,
        zero_vars: &HashSet<String>,
    ) {
        // Get the function/macro name
        if let Some(function) = node.child_by_field_name("function") {
            let func_name = ast_utils::get_node_text(&function, source);

            // Check if this is a known division macro
            if let Some(macro_info) = division_macros.get(func_name) {
                // Get the arguments
                if let Some(args) = node.child_by_field_name("arguments") {
                    let mut arg_idx = 0;
                    for i in 0..args.child_count() {
                        if let Some(arg) = args.child(i) {
                            // Skip parentheses and commas
                            if arg.kind() == "(" || arg.kind() == ")" || arg.kind() == "," {
                                continue;
                            }

                            // Check if this is the divisor argument
                            if arg_idx == macro_info.divisor_param_index {
                                let arg_text = ast_utils::get_node_text(&arg, source);

                                // Check if divisor is zero literal or a zero-initialized variable
                                if arg_text == "0" || zero_vars.contains(arg_text) {
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: self.severity(),
                                        message: format!(
                                            "Macro '{}' called with divisor '{}' that may be zero",
                                            func_name, arg_text
                                        ),
                                        file_path: String::new(),
                                        line: node.start_position().row + 1,
                                        column: node.start_position().column + 1,
                                        suggestion: Some(
                                            "Check if divisor is not zero before calling division macro".to_string(),
                                        ),
                                        ..Default::default()
                                    });
                                    return;
                                }
                            }
                            arg_idx += 1;
                        }
                    }
                }
            }
        }
    }

    /// Check if a division or modulo operation is safe
    fn check_division_safety(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(right) = node.child_by_field_name("right") {
            let right_text = ast_utils::get_node_text(&right, source);

            // Check for direct division by zero
            if right_text == "0" {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: "Division or modulo by zero literal".to_string(),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(
                        "Ensure divisor is not zero before performing operation".to_string(),
                    ),
                    ..Default::default()
                });
                return;
            }

            // Check if divisor is a variable, array element, field, expression, pointer dereference, or function call that might be zero
            // Look for preceding check
            if (right.kind() == "identifier"
                || right.kind() == "field_expression"
                || right.kind() == "subscript_expression"  // Array/pointer subscript like divisors[i]
                || right.kind() == "call_expression" // Function calls like get_divisor()
                || right.kind() == "binary_expression" // Expressions like (a - b)
                || right.kind() == "parenthesized_expression" // Parenthesized expressions
                || right.kind() == "pointer_expression" // Pointer dereference like *ptr
                || right.kind() == "unary_expression")
                && !self.is_divisor_checked(node, &right, source)
            {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Division or modulo by '{}' without checking for zero",
                        right_text
                    ),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(format!(
                        "Check if '{}' is not zero before division",
                        right_text
                    )),
                    ..Default::default()
                });
            }
        }
    }

    /// Check if a compound assignment (/= or %=) is safe
    fn check_compound_assignment_safety(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(right) = node.child_by_field_name("right") {
            let right_text = ast_utils::get_node_text(&right, source);

            // Check for direct division by zero
            if right_text == "0" {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: "Compound assignment with zero divisor".to_string(),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(
                        "Ensure divisor is not zero before performing operation".to_string(),
                    ),
                    ..Default::default()
                });
                return;
            }

            // Check if divisor is a variable, array element, field, expression, pointer dereference, or function call that might be zero
            if (right.kind() == "identifier"
                || right.kind() == "field_expression"
                || right.kind() == "subscript_expression"
                || right.kind() == "call_expression"
                || right.kind() == "binary_expression"
                || right.kind() == "parenthesized_expression"
                || right.kind() == "pointer_expression"
                || right.kind() == "unary_expression")
                && !self.is_divisor_checked(node, &right, source)
            {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Compound assignment with '{}' without checking for zero",
                        right_text
                    ),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(format!(
                        "Check if '{}' is not zero before division",
                        right_text
                    )),
                    ..Default::default()
                });
            }
        }
    }

    /// Check if a divisor has been validated as non-zero
    fn is_divisor_checked(&self, div_node: &Node, divisor: &Node, source: &str) -> bool {
        let divisor_text = ast_utils::get_node_text(divisor, source);

        // Fast path: compile-time constant expression — evaluate and check non-zero.
        // Covers macros like `BRIGHTNESS_MAX 255`, enum values, and numeric literals.
        {
            let macros = self.file_macros.borrow();
            if let Some(val) = const_eval::try_evaluate_expr(divisor, source, &macros) {
                return val != 0;
            }
        }

        // Extract base variable name from complex expressions
        let base_var_name = Self::extract_base_variable(divisor, source);

        // For struct field accesses like frac->denominator, check if there's validation
        // in the struct's initialization or constructor function
        if divisor.kind() == "field_expression" && self.is_struct_field_validated(divisor, source) {
            return true;
        }

        // Find the containing function
        if let Some(func) = ast_utils::find_containing_function(div_node) {
            if let Some(body) = func.child_by_field_name("body") {
                // Check if there's an early return or error handling for zero divisor
                // Check both the full expression and the base variable
                if self.has_early_return_for_zero(&body, divisor_text, source, div_node)
                    || (base_var_name != divisor_text
                        && self.has_early_return_for_zero(&body, &base_var_name, source, div_node))
                {
                    return true;
                }
            }
        }

        // Find the containing statement or block
        let mut current = div_node.parent();
        while let Some(node) = current {
            // Look for if statements that check the divisor
            if node.kind() == "if_statement" {
                if let Some(condition) = node.child_by_field_name("condition") {
                    if self.checks_for_zero(&condition, divisor_text, source)
                        || (base_var_name != divisor_text
                            && self.checks_for_zero(&condition, &base_var_name, source))
                    {
                        // Check if we're in the else branch or the consequence after a zero check
                        if self.is_in_safe_branch(&node, div_node) {
                            return true;
                        }
                    }
                    // Also check for fabs/fabsf/fabsl magnitude guards
                    // e.g., if(fabs(data) > 0.000001) { ... / data; }
                    if Self::is_fabs_guard(&condition, divisor_text, source)
                        || (base_var_name != divisor_text
                            && Self::is_fabs_guard(&condition, &base_var_name, source))
                    {
                        if self.is_in_safe_branch(&node, div_node) {
                            return true;
                        }
                    }
                }
            }

            current = node.parent();
        }

        // Value-range analysis: check if enclosing conditions prove divisor >= 1
        // This catches patterns like `if (lower < upper) { total / (upper - lower); }`
        if self.divisor_provably_nonzero(div_node, divisor, source) {
            return true;
        }

        // Check if ALL assignments to the divisor variable in the containing
        // function are provably non-zero constants.  This catches the common
        // Juliet "goodG2B" pattern: `data = -1; data = 7; 100 / data;`
        if divisor.kind() == "identifier"
            && self.all_assignments_nonzero(div_node, divisor_text, source)
        {
            return true;
        }

        false
    }

    /// Extract the base variable name from an expression
    /// For example: (-step) -> step, (*ptr) -> ptr, frac->denominator -> denominator
    fn extract_base_variable(node: &Node, source: &str) -> String {
        match node.kind() {
            "identifier" => ast_utils::get_node_text(node, source).to_string(),
            "parenthesized_expression" => {
                // Look inside parentheses
                if let Some(child) = node.named_child(0) {
                    Self::extract_base_variable(&child, source)
                } else {
                    ast_utils::get_node_text(node, source).to_string()
                }
            }
            "unary_expression" | "pointer_expression" => {
                // For unary like (-step) or (*ptr), extract the argument
                if let Some(argument) = node.child_by_field_name("argument") {
                    Self::extract_base_variable(&argument, source)
                } else {
                    ast_utils::get_node_text(node, source).to_string()
                }
            }
            "field_expression" => {
                // For field like frac->denominator, extract the field name
                if let Some(field) = node.child_by_field_name("field") {
                    ast_utils::get_node_text(&field, source).to_string()
                } else {
                    ast_utils::get_node_text(node, source).to_string()
                }
            }
            _ => ast_utils::get_node_text(node, source).to_string(),
        }
    }

    /// Check if there's an early return or exit when divisor is zero.
    /// Recurses into nested blocks (if-bodies, compound statements) to find
    /// guards like `if (expr == 0) { return; }` at any nesting depth.
    fn has_early_return_for_zero(
        &self,
        scope: &Node,
        var_name: &str,
        source: &str,
        div_node: &Node,
    ) -> bool {
        let div_line = div_node.start_position().row;

        for i in 0..scope.named_child_count() {
            if let Some(child) = scope.named_child(i) {
                let child_line = child.start_position().row;

                // Only check statements before the division
                if child_line >= div_line {
                    break;
                }

                if child.kind() == "if_statement" {
                    if let Some(condition) = child.child_by_field_name("condition") {
                        if self.checks_for_zero(&condition, var_name, source) {
                            if let Some(consequence) = child.child_by_field_name("consequence") {
                                if Self::has_return_or_exit(&consequence, source) {
                                    return true;
                                }
                            }
                        }
                    }
                    // Recurse into if-body to find guards at deeper nesting
                    if let Some(consequence) = child.child_by_field_name("consequence") {
                        if self.has_early_return_for_zero(&consequence, var_name, source, div_node)
                        {
                            return true;
                        }
                    }
                }

                // Recurse into bare compound statements
                if child.kind() == "compound_statement" {
                    if self.has_early_return_for_zero(&child, var_name, source, div_node) {
                        return true;
                    }
                }

                // Check for do-while loops that validate input
                if child.kind() == "do_statement" {
                    if let Some(condition) = child.child_by_field_name("condition") {
                        if self.checks_for_zero(&condition, var_name, source) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Check if a branch contains return or exit
    fn has_return_or_exit(node: &Node, source: &str) -> bool {
        let text = ast_utils::get_node_text(node, source);

        if text.contains("return") || text.contains("exit") || text.contains("abort") {
            return true;
        }

        // Also check child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "return_statement"
                    || child.kind() == "break_statement"
                    || child.kind() == "continue_statement"
                {
                    return true;
                }
                if Self::has_return_or_exit(&child, source) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if division node is in a safe branch (e.g., in the body after a zero check)
    fn is_in_safe_branch(&self, if_node: &Node, div_node: &Node) -> bool {
        // Check if div_node is a descendant of the if_statement's consequence
        if let Some(consequence) = if_node.child_by_field_name("consequence") {
            if Self::is_descendant(&consequence, div_node) {
                return true;
            }
        }

        // Check if there's an alternative (else) branch
        if let Some(alternative) = if_node.child_by_field_name("alternative") {
            if Self::is_descendant(&alternative, div_node) {
                return true;
            }
        }

        false
    }

    /// Check if target is a descendant of node (O(1) via byte-range containment)
    fn is_descendant(node: &Node, target: &Node) -> bool {
        target.start_byte() >= node.start_byte() && target.end_byte() <= node.end_byte()
    }

    /// Check if a condition expression checks for zero
    fn checks_for_zero(&self, condition: &Node, var_name: &str, source: &str) -> bool {
        let condition_text = ast_utils::get_node_text(condition, source);

        // Look for patterns like:
        // - var == 0
        // - var != 0
        // - 0 == var
        // - !var
        // - var (truthy check)

        // Simple text-based check for common patterns
        if condition_text.contains(&format!("{} == 0", var_name))
            || condition_text.contains(&format!("{} != 0", var_name))
            || condition_text.contains(&format!("0 == {}", var_name))
            || condition_text.contains(&format!("0 != {}", var_name))
            || condition_text.contains(&format!("!{}", var_name))
        {
            return true;
        }

        // Also recursively check child nodes
        for i in 0..condition.child_count() {
            if let Some(child) = condition.child(i) {
                if child.kind() == "binary_expression" {
                    if let Some(operator) = ast_utils::get_binary_operator(&child, source) {
                        if operator == "==" || operator == "!=" {
                            let left = child.child_by_field_name("left");
                            let right = child.child_by_field_name("right");

                            if let (Some(l), Some(r)) = (left, right) {
                                let left_text = ast_utils::get_node_text(&l, source);
                                let right_text = ast_utils::get_node_text(&r, source);

                                if (left_text == var_name && right_text == "0")
                                    || (right_text == var_name && left_text == "0")
                                {
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

    /// Use value-range analysis to prove a divisor is provably non-zero.
    ///
    /// First tries CFG-based VRA (if available), which handles sequential
    /// assignments, conditional narrowing through arbitrary paths, and
    /// early-return guard patterns. Falls back to syntactic ancestor walks.
    fn divisor_provably_nonzero(&self, div_node: &Node, divisor: &Node, source: &str) -> bool {
        let file_macros = self.file_macros.borrow();

        // Try CFG-based VRA first (more precise)
        if let Some(range) = self.eval_divisor_range_via_vra(div_node, divisor, source) {
            if range.min >= 1 || range.max <= -1 {
                return true;
            }
        }

        // Fallback: syntactic ancestor walk (loop bounds + if-condition bounds)
        let mut var_ranges = const_eval::extract_loop_var_ranges(div_node, source, &file_macros);
        Self::extract_if_condition_ranges(div_node, source, &file_macros, &mut var_ranges);

        if let Some(range) =
            const_eval::try_evaluate_range(divisor, source, &file_macros, &var_ranges)
        {
            if range.min >= 1 || range.max <= -1 {
                return true;
            }
        }

        false
    }

    /// Evaluate the divisor's range using CFG-based VRA.
    fn eval_divisor_range_via_vra(
        &self,
        div_node: &Node,
        divisor: &Node,
        source: &str,
    ) -> Option<ValueRange> {
        let vra_results = self.vra_results.borrow();
        let cfgs = self.function_cfgs.borrow();
        let file_macros = self.file_macros.borrow();

        if vra_results.is_empty() || cfgs.is_empty() {
            return None;
        }

        // Find the containing function to get its CFG and VRA result
        let func = ast_utils::find_containing_function(div_node)?;
        let start_byte = func.start_byte();
        let cfg = cfgs.get(&start_byte)?;
        let vra = vra_results.get(&start_byte)?;
        let body = func.child_by_field_name("body")?;

        value_range::eval_expr_range_at(vra, cfg, &body, source, &file_macros, divisor)
    }

    /// Check if a condition is a floating-point magnitude guard like
    /// `fabs(var) > 0.000001`.  This implies `var` is non-zero.
    fn is_fabs_guard(condition: &Node, var_name: &str, source: &str) -> bool {
        let cond_text = ast_utils::get_node_text(condition, source);
        // Must contain fabs/fabsf/fabsl of the variable and a > comparison
        let has_fabs = (cond_text.contains("fabs(")
            || cond_text.contains("fabsf(")
            || cond_text.contains("fabsl("))
            && cond_text.contains(var_name)
            && cond_text.contains('>');
        if has_fabs {
            return true;
        }
        // Also handle compound conditions with &&
        if condition.kind() == "binary_expression" || condition.kind() == "parenthesized_expression"
        {
            for i in 0..condition.named_child_count() {
                if let Some(child) = condition.named_child(i) {
                    if Self::is_fabs_guard(&child, var_name, source) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Walk up to enclosing if_statement ancestors and extract variable
    /// bounds from their conditions. Only applies when the division is
    /// inside the consequence (then-branch) of the if — the condition is
    /// known to be true on that path.
    fn extract_if_condition_ranges(
        node: &Node,
        source: &str,
        macros: &MacroConstantMap,
        ranges: &mut VarRangeMap,
    ) {
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "if_statement" {
                // Only extract if we're in the consequence (then) branch
                if let Some(consequence) = parent.child_by_field_name("consequence") {
                    if Self::is_descendant(&consequence, node) {
                        if let Some(condition) = parent.child_by_field_name("condition") {
                            Self::extract_comparison_bounds(&condition, source, macros, ranges);
                        }
                    }
                }
            } else if parent.kind() == "function_definition" || parent.kind() == "translation_unit"
            {
                break;
            }
            current = parent.parent();
        }
    }

    /// Extract variable bounds from comparison expressions.
    /// Handles: a < b, a > b, a <= b, a >= b, a != b (with literals),
    /// and compound && conditions.
    fn extract_comparison_bounds(
        condition: &Node,
        source: &str,
        macros: &MacroConstantMap,
        ranges: &mut VarRangeMap,
    ) {
        // Unwrap parenthesized_expression
        let cond = if condition.kind() == "parenthesized_expression" {
            condition.child(1).unwrap_or(*condition)
        } else {
            *condition
        };

        if cond.kind() != "binary_expression" {
            return;
        }

        let op = ast_utils::get_binary_operator(&cond, source).unwrap_or_default();

        // Handle compound && conditions
        if op == "&&" {
            if let Some(left) = cond.child_by_field_name("left") {
                Self::extract_comparison_bounds(&left, source, macros, ranges);
            }
            if let Some(right) = cond.child_by_field_name("right") {
                Self::extract_comparison_bounds(&right, source, macros, ranges);
            }
            return;
        }

        let (left, right) = match (
            cond.child_by_field_name("left"),
            cond.child_by_field_name("right"),
        ) {
            (Some(l), Some(r)) => (l, r),
            _ => return,
        };

        let left_text = ast_utils::get_node_text(&left, source);
        let right_text = ast_utils::get_node_text(&right, source);

        match op {
            "<" => {
                // left < right → left ∈ [_, right-1]
                if left.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&right, source, macros) {
                        let entry = ranges
                            .entry(left_text.to_string())
                            .or_insert(ValueRange::new(i64::MIN / 2, bound - 1));
                        if bound - 1 < entry.max {
                            entry.max = bound - 1;
                        }
                    }
                }
                // left < right → right ∈ [left+1, _]
                if right.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&left, source, macros) {
                        let entry = ranges
                            .entry(right_text.to_string())
                            .or_insert(ValueRange::new(bound + 1, i64::MAX / 2));
                        if bound + 1 > entry.min {
                            entry.min = bound + 1;
                        }
                    }
                }
            }
            "<=" => {
                if left.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&right, source, macros) {
                        let entry = ranges
                            .entry(left_text.to_string())
                            .or_insert(ValueRange::new(i64::MIN / 2, bound));
                        if bound < entry.max {
                            entry.max = bound;
                        }
                    }
                }
                if right.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&left, source, macros) {
                        let entry = ranges
                            .entry(right_text.to_string())
                            .or_insert(ValueRange::new(bound, i64::MAX / 2));
                        if bound > entry.min {
                            entry.min = bound;
                        }
                    }
                }
            }
            ">" => {
                // left > right → left ∈ [right+1, _]
                if left.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&right, source, macros) {
                        let entry = ranges
                            .entry(left_text.to_string())
                            .or_insert(ValueRange::new(bound + 1, i64::MAX / 2));
                        if bound + 1 > entry.min {
                            entry.min = bound + 1;
                        }
                    }
                }
                if right.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&left, source, macros) {
                        let entry = ranges
                            .entry(right_text.to_string())
                            .or_insert(ValueRange::new(i64::MIN / 2, bound - 1));
                        if bound - 1 < entry.max {
                            entry.max = bound - 1;
                        }
                    }
                }
            }
            ">=" => {
                if left.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&right, source, macros) {
                        let entry = ranges
                            .entry(left_text.to_string())
                            .or_insert(ValueRange::new(bound, i64::MAX / 2));
                        if bound > entry.min {
                            entry.min = bound;
                        }
                    }
                }
                if right.kind() == "identifier" {
                    if let Some(bound) = const_eval::try_evaluate_expr(&left, source, macros) {
                        let entry = ranges
                            .entry(right_text.to_string())
                            .or_insert(ValueRange::new(i64::MIN / 2, bound));
                        if bound < entry.max {
                            entry.max = bound;
                        }
                    }
                }
            }
            "!=" => {
                // var != 0 establishes var ∈ [-inf, -1] ∪ [1, inf]
                // We can't represent a gap, but if one side is 0, we know
                // the range excludes zero. We'll handle this separately
                // in divisor_provably_nonzero via the ne_zero check.
            }
            _ => {}
        }
    }

    /// Check if ALL assignments to `var_name` in the containing function are
    /// provably non-zero constants.  Returns false if any assignment is unknown,
    /// zero, or if the variable is a function parameter (no assignments found).
    fn all_assignments_nonzero(&self, div_node: &Node, var_name: &str, source: &str) -> bool {
        let func = match ast_utils::find_containing_function(div_node) {
            Some(f) => f,
            None => return false,
        };
        let body = match func.child_by_field_name("body") {
            Some(b) => b,
            None => return false,
        };
        let file_macros = self.file_macros.borrow();
        let mut found_any = false;
        if !Self::collect_assignments_all_nonzero(
            &body,
            var_name,
            source,
            &file_macros,
            &mut found_any,
        ) {
            return false;
        }
        // Also check the declaration initializer (e.g., `int data = -1;`)
        // which is inside the body but might also be a parameter — check params
        // If no assignments found at all (e.g., parameter), can't prove non-zero
        found_any
    }

    /// Recursively walk `scope` collecting assignments to `var_name`.
    /// Returns false immediately if any assignment is zero or non-constant.
    fn collect_assignments_all_nonzero(
        scope: &Node,
        var_name: &str,
        source: &str,
        macros: &MacroConstantMap,
        found_any: &mut bool,
    ) -> bool {
        for i in 0..scope.named_child_count() {
            let child = match scope.named_child(i) {
                Some(c) => c,
                None => continue,
            };

            match child.kind() {
                "declaration" => {
                    // Check `int data = EXPR;`
                    if Self::declaration_assigns_to(&child, var_name, source) {
                        if let Some(val_node) =
                            Self::declaration_init_value(&child, var_name, source)
                        {
                            if !Self::is_nonzero_constant(&val_node, source, macros) {
                                return false;
                            }
                            *found_any = true;
                        }
                        // `int data;` without init — not an assignment
                    }
                }
                "expression_statement" => {
                    // Check `data = EXPR;`
                    if let Some(expr) = child.named_child(0) {
                        if expr.kind() == "assignment_expression" {
                            if let Some(lhs) = expr.child_by_field_name("left") {
                                if lhs.kind() == "identifier"
                                    && ast_utils::get_node_text(&lhs, source) == var_name
                                {
                                    if let Some(rhs) = expr.child_by_field_name("right") {
                                        if !Self::is_nonzero_constant(&rhs, source, macros) {
                                            return false;
                                        }
                                        *found_any = true;
                                    }
                                }
                            }
                        }
                        // Check for update_expression (i++, i--, ++i, --i)
                        // or compound assignments (+=, -=, etc.) that modify the variable
                        if Self::is_variable_modified_by_update(&expr, var_name, source) {
                            return false;
                        }
                    }
                }
                // Also check for-loop update expressions (the update clause of for(;;update))
                "for_statement" => {
                    // Check if the for-loop's update or body modifies the variable
                    let text = ast_utils::get_node_text(&child, source);
                    if text.contains(var_name) {
                        if let Some(update) = child.child_by_field_name("update") {
                            if Self::is_variable_modified_by_update(&update, var_name, source) {
                                return false;
                            }
                        }
                    }
                    // Still recurse into the for body
                    if !Self::collect_assignments_all_nonzero(
                        &child, var_name, source, macros, found_any,
                    ) {
                        return false;
                    }
                }
                _ => {
                    // Recurse into compound statements, if-bodies, etc.
                    if !Self::collect_assignments_all_nonzero(
                        &child, var_name, source, macros, found_any,
                    ) {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Check if `node` contains an update expression (++, --, +=, -=, etc.)
    /// that modifies `var_name`. Returns true if found.
    fn is_variable_modified_by_update(node: &Node, var_name: &str, source: &str) -> bool {
        match node.kind() {
            "update_expression" => {
                // i++, i--, ++i, --i
                let text = ast_utils::get_node_text(node, source);
                text.contains(var_name)
            }
            "assignment_expression" => {
                // Check for compound assignments (+=, -=, *=, /=, etc.)
                if let Some(lhs) = node.child_by_field_name("left") {
                    if lhs.kind() == "identifier"
                        && ast_utils::get_node_text(&lhs, source) == var_name
                    {
                        let full_text = ast_utils::get_node_text(node, source);
                        if full_text.contains("+=")
                            || full_text.contains("-=")
                            || full_text.contains("*=")
                            || full_text.contains("/=")
                            || full_text.contains("%=")
                        {
                            return true;
                        }
                    }
                }
                false
            }
            _ => {
                for i in 0..node.named_child_count() {
                    if let Some(child) = node.named_child(i) {
                        if Self::is_variable_modified_by_update(&child, var_name, source) {
                            return true;
                        }
                    }
                }
                false
            }
        }
    }

    /// Check if `node` evaluates to a provably non-zero constant.
    fn is_nonzero_constant(node: &Node, source: &str, macros: &MacroConstantMap) -> bool {
        // Try integer const_eval first
        if let Some(val) = const_eval::try_evaluate_expr(node, source, macros) {
            return val != 0;
        }
        // Try float literal (e.g., 2.0F, 1e-40, -3.14)
        if let Some(val) = Self::try_parse_float_literal(node, source) {
            return val != 0.0;
        }
        false
    }

    /// Try to parse a node as a floating-point literal, handling suffixes and
    /// unary negation.
    fn try_parse_float_literal(node: &Node, source: &str) -> Option<f64> {
        match node.kind() {
            "number_literal" => {
                let text = ast_utils::get_node_text(node, source);
                let text = text
                    .trim_end_matches('f')
                    .trim_end_matches('F')
                    .trim_end_matches('l')
                    .trim_end_matches('L');
                text.parse::<f64>().ok()
            }
            "unary_expression" => {
                // Handle -(literal)
                let op = node.child(0).map(|c| ast_utils::get_node_text(&c, source));
                let arg = node.child_by_field_name("argument")?;
                if op == Some("-") {
                    Self::try_parse_float_literal(&arg, source).map(|v| -v)
                } else {
                    None
                }
            }
            "parenthesized_expression" => {
                let inner = node.named_child(0)?;
                Self::try_parse_float_literal(&inner, source)
            }
            _ => None,
        }
    }

    /// Check if a declaration assigns to `var_name`.
    fn declaration_assigns_to(decl: &Node, var_name: &str, source: &str) -> bool {
        for i in 0..decl.named_child_count() {
            if let Some(child) = decl.named_child(i) {
                if child.kind() == "init_declarator" {
                    // Look for the identifier
                    for j in 0..child.named_child_count() {
                        if let Some(gc) = child.named_child(j) {
                            if gc.kind() == "identifier"
                                && ast_utils::get_node_text(&gc, source) == var_name
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Get the initializer value node from a declaration like `int data = EXPR;`.
    fn declaration_init_value<'a>(
        decl: &'a Node<'a>,
        var_name: &str,
        source: &str,
    ) -> Option<Node<'a>> {
        for i in 0..decl.named_child_count() {
            if let Some(child) = decl.named_child(i) {
                if child.kind() == "init_declarator" {
                    let mut found_name = false;
                    let mut value_node = None;
                    for j in 0..child.named_child_count() {
                        if let Some(gc) = child.named_child(j) {
                            if gc.kind() == "identifier"
                                && ast_utils::get_node_text(&gc, source) == var_name
                            {
                                found_name = true;
                            } else if found_name && gc.kind() != "=" {
                                value_node = Some(gc);
                                break;
                            }
                        }
                    }
                    if found_name {
                        return value_node;
                    }
                }
            }
        }
        None
    }

    /// Check if a struct field is validated for non-zero in a constructor/setter
    /// This provides basic inter-procedural analysis for struct invariants
    fn is_struct_field_validated(&self, field_expr: &Node, source: &str) -> bool {
        // Extract the field name from expressions like frac->denominator or obj.field
        if let Some(field) = field_expr.child_by_field_name("field") {
            let field_name = ast_utils::get_node_text(&field, source);

            // Look for validation patterns in the source file where this field (or abbreviated name) is checked for zero
            // For example, parameter "denom" might represent field "denominator"
            // Also check common abbreviations
            let mut possible_names = vec![field_name.to_string()];

            // Add common abbreviations (e.g., "denominator" -> "denom", "numerator" -> "num")
            if field_name.len() > 5 {
                possible_names.push(field_name[..4].to_string()); // First 4 chars
                possible_names.push(field_name[..5].to_string()); // First 5 chars
            }

            // Search for any of these names being checked against zero with error handling
            let lines: Vec<&str> = source.lines().collect();
            for possible_name in &possible_names {
                for (idx, line) in lines.iter().enumerate() {
                    // Check if this line validates the name for zero
                    if (line.contains(&format!("{} == 0", possible_name))
                        || line.contains(&format!("{} != 0", possible_name))
                        || line.contains(&format!("0 == {}", possible_name)))
                        && (line.contains("if") || line.contains("IF"))
                    {
                        // Look in the next few lines for error handling (return/exit/abort)
                        for check_line in lines.iter().skip(idx).take(10) {
                            if check_line.contains("return false")
                                || check_line.contains("return NULL")
                                || check_line.contains("return -1")
                                || check_line.contains("return 0")
                                || check_line.contains("exit(")
                                || check_line.contains("abort(")
                                || check_line.contains("Error:")
                                || check_line.contains("printf(\"Error")
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_c_code(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c::language())
            .expect("Error loading C grammar");
        parser.parse(source, None).expect("Error parsing C code")
    }

    #[test]
    fn test_direct_zero_division() {
        let code = r#"
int main() {
    int x = 10;
    int result = x / 0;
    return 0;
}
"#;
        let tree = parse_c_code(code);
        let rule = Int33C::new();
        let violations = rule.check(&tree.root_node(), code);
        assert!(
            !violations.is_empty(),
            "Should detect direct division by zero"
        );
    }

    #[test]
    fn test_unchecked_division() {
        let code = r#"
void func(int a, int b) {
    int result = a / b;
}
"#;
        let tree = parse_c_code(code);
        let rule = Int33C::new();
        let violations = rule.check(&tree.root_node(), code);
        assert!(!violations.is_empty(), "Should detect unchecked division");
    }

    #[test]
    fn test_checked_division() {
        let code = r#"
void func(int a, int b) {
    if (b != 0) {
        int result = a / b;
    }
}
"#;
        let tree = parse_c_code(code);
        let rule = Int33C::new();
        let violations = rule.check(&tree.root_node(), code);
        assert!(violations.is_empty(), "Should not flag checked division");
    }
}
