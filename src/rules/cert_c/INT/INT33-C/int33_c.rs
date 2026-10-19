// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::FunctionCfg;
use crate::analyze::check_macros;
use crate::analyze::const_eval::{self, MacroConstantMap, ValueRange, VarRangeMap};
use crate::analyze::context::{ProjectContext, VisibleTypes};
use crate::analyze::noreturn::ByNoreturnTrust;
use crate::analyze::value_range::{self, RangeAnalysisResult};
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils;
use crate::utility::cert_c::expr_type::{self, TypeEnv};
use crate::utility::cert_c::float_typing;
use crate::utility::cert_c::guard_dominance;
use crate::utility::cert_c::node_children::NodeChildren;
use crate::utility::cert_c::nonzero_facts;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tree_sitter::Node;

pub struct Int33C {
    project_macros: RefCell<Arc<MacroConstantMap>>,
    /// Cached per-file macro constants (set once per check() call, avoids re-collecting per division node)
    file_macros: RefCell<MacroConstantMap>,
    /// Per-function CFGs (set by set_function_cfgs)
    function_cfgs: RefCell<Arc<HashMap<usize, FunctionCfg>>>,
    /// Per-function VRA results (set by set_vra_results)
    vra_results: RefCell<Arc<HashMap<usize, RangeAnalysisResult>>>,
    /// The typedefs and struct fields this file sees, for typing a
    /// division's operands by declaration.
    visible: RefCell<VisibleTypes>,
    /// Assert-style macros no configuration compiles out, with the index of
    /// the parameter each checks (`ProjectContext::abort_check_macros`),
    /// under each noreturn setting (`ByNoreturnTrust`).
    abort_check_macros: RefCell<ByNoreturnTrust<Arc<HashMap<String, usize>>>>,
    /// The prescan's cross-file noreturn functions
    /// (`ProjectContext::noreturn_functions`), under each noreturn setting.
    noreturn_functions: RefCell<ByNoreturnTrust<Arc<HashSet<String>>>>,
    /// The functions a call in the current file never returns from: the
    /// above for the run's settings, plus the file's own (set once per
    /// check() call).
    file_noreturn_names: RefCell<HashSet<String>>,
    /// The run's policy and environment settings: whether an
    /// NDEBUG-strippable assert guards a division (`assert_is_guard`).
    settings: RefCell<Arc<AnalysisSettings>>,
    /// Per file: whether every caller of a closed function passes a non-zero
    /// value at a parameter, keyed by the function's start byte and the
    /// parameter's index (`every_caller_passes_nonzero`).
    caller_proofs: RefCell<HashMap<(usize, usize), bool>>,
    /// The path of the file being checked: the caller proof holds only for
    /// a `.c` file's own functions.
    file_path: RefCell<Option<PathBuf>>,
}

impl Int33C {
    pub fn new() -> Self {
        Self {
            project_macros: RefCell::new(Arc::new(MacroConstantMap::new())),
            file_macros: RefCell::new(MacroConstantMap::new()),
            function_cfgs: RefCell::new(Arc::default()),
            vra_results: RefCell::new(Arc::default()),
            visible: RefCell::default(),
            abort_check_macros: RefCell::default(),
            noreturn_functions: RefCell::default(),
            file_noreturn_names: RefCell::default(),
            settings: RefCell::default(),
            caller_proofs: RefCell::default(),
            file_path: RefCell::default(),
        }
    }
}

/// Which preceding check statements count as a divisor guard.
struct GuardCredit<'a> {
    /// `assert_is_guard`: an `NDEBUG`-strippable assert counts.
    assert_is_guard: bool,
    /// Check macros no configuration compiles out, with the index of the
    /// parameter each checks; these count under every policy.
    checks: &'a HashMap<String, usize>,
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
    fn reads_header_facts(&self) -> bool {
        true
    }

    fn rule_id(&self) -> &'static str {
        "INT33-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that division and remainder operations do not result in divide-by-zero errors"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "INT33-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_macros.borrow_mut() = context.macro_constants.clone();
        *self.abort_check_macros.borrow_mut() = context.abort_check_macros.clone();
        *self.noreturn_functions.borrow_mut() = context.noreturn_functions.clone();
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        *self.settings.borrow_mut() = Arc::clone(settings);
    }

    fn set_visible_types(&self, types: &VisibleTypes) {
        *self.visible.borrow_mut() = types.clone();
    }

    fn set_file_path(&self, path: &Path) {
        *self.file_path.borrow_mut() = Some(path.to_path_buf());
    }

    fn set_function_cfgs(&self, cfgs: &Arc<HashMap<usize, FunctionCfg>>) {
        *self.function_cfgs.borrow_mut() = Arc::clone(cfgs);
    }

    fn set_vra_results(&self, results: &Arc<HashMap<usize, RangeAnalysisResult>>) {
        *self.vra_results.borrow_mut() = Arc::clone(results);
    }

    fn needs_vra(&self) -> bool {
        true
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Cache per-file macro constants once (avoid re-collecting per division node).
        // Merge project-level macros with per-file macros (per-file wins).
        *self.file_macros.borrow_mut() = const_eval::merged_macro_constants(
            &self.project_macros.borrow(),
            node,
            source,
            self.settings.borrow().facts,
        );

        let settings = Arc::clone(&self.settings.borrow());
        *self.file_noreturn_names.borrow_mut() = crate::analyze::noreturn::noreturn_names_for_file(
            self.noreturn_functions.borrow().get(&settings),
            node,
            source,
            &settings,
        );

        self.caller_proofs.borrow_mut().clear();

        // First pass: find division macros and zero-initialized variables
        let division_macros = self.find_division_macros(source);
        let zero_vars = self.find_zero_initialized_vars(node, source);

        // Check for division or modulo operations. Operands are typed by
        // declaration, so a floating operand suppresses the integer
        // divide-by-zero check.
        let visible = self.visible.borrow();
        let env = TypeEnv::visible(&visible, self.settings.borrow().facts).in_tree(*node);
        self.check_node(
            node,
            source,
            &mut violations,
            &division_macros,
            &zero_vars,
            &env,
        );

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
                            // Search from the '(' so a ')' before it (a malformed
                            // `#define`) cannot make the slice start past its end.
                            if let Some(params_len) = name_part[paren_pos + 1..].find(')') {
                                let params = &name_part[paren_pos + 1..paren_pos + 1 + params_len];
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
        for decl in query::find_descendants_of_kinds(*node, &["declaration", "init_declarator"]) {
            // Look for pattern: type var = 0
            let decl_text = ast_utils::get_node_text(&decl, source);
            if decl_text.contains("= 0") || decl_text.ends_with("= 0;") {
                // Extract variable name
                if let Some(name) = self.extract_declared_var_name(&decl, source) {
                    zero_vars.insert(name);
                }
            }
        }
        zero_vars
    }

    fn extract_declared_var_name(&self, node: &Node, source: &str) -> Option<String> {
        for child in node.child_nodes() {
            if child.kind() == "init_declarator" {
                // Look for identifier in init_declarator
                for grandchild in child.child_nodes() {
                    if grandchild.kind() == "identifier" {
                        return Some(ast_utils::get_node_text(&grandchild, source).to_string());
                    }
                }
            } else if child.kind() == "identifier" {
                return Some(ast_utils::get_node_text(&child, source).to_string());
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
        env: &TypeEnv,
    ) {
        // Check for division or modulo operations
        if node.kind() == "binary_expression" {
            if let Some(operator) = ast_utils::get_binary_operator(node, source) {
                if operator == "/" || operator == "%" {
                    self.check_division_safety(node, source, violations, env);
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
                    for child in node.child_nodes() {
                        if child.kind() == "/=" || child.kind() == "%=" {
                            self.check_compound_assignment_safety(node, source, violations, env);
                            break;
                        }
                        let text = ast_utils::get_node_text(&child, source);
                        if text == "/=" || text == "%=" {
                            self.check_compound_assignment_safety(node, source, violations, env);
                            break;
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
        for child in node.child_nodes() {
            self.check_node(&child, source, violations, division_macros, zero_vars, env);
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
                    for arg in args.child_nodes() {
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

    /// Check if a division or modulo operation is safe
    fn check_division_safety(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        env: &TypeEnv,
    ) {
        // A `/` inside a preprocessor directive tree-sitter could not place is
        // not a division: `#if __has_include(<sys/socket.h>)` reparses with the
        // header PATH's separator as an operator, yielding "division by
        // 'socket'". No arithmetic is evaluated on a directive line (ADR-0008).
        if ast_utils::is_on_preproc_directive_line(source, node.start_byte()) {
            return;
        }

        // Nor is a `/` or `%` that the source shows is inside a string literal:
        // an ERROR region can swallow the quote delimiters, after which
        // `"Line %d: Invalid bss_load_test"` reparses as arithmetic over its
        // own contents (hostap config_file.c:4252). The operator node is real;
        // only the source shows it was text (ADR-0008).
        if ast_utils::is_in_string_or_char_literal(source, node.start_byte()) {
            return;
        }

        // INT33-C concerns INTEGER divide-by-zero. A floating division by zero
        // is undefined too in ISO C (C11 6.5.5p5), but it is FLP03-C's, so
        // skip when either operand is float-typed — matching C's
        // usual-arithmetic-conversion rules.
        if self.division_is_floating(node, source, env) {
            return;
        }

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
                && !self.is_divisor_checked(node, &right, source, env)
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
        env: &TypeEnv,
    ) {
        // Floating-point `/=`/`%=` is not integer divide-by-zero UB; skip when
        // either operand is float-typed.
        if self.division_is_floating(node, source, env) {
            return;
        }

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
                && !self.is_divisor_checked(node, &right, source, env)
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

    /// Check if a divisor has been validated as non-zero.
    ///
    /// Every credit is a proof about the divisor at the division: a constant,
    /// a condition known to hold there (`nonzero_facts::known_conditions`), an
    /// assert or check macro before it, a value range, every assignment in
    /// the function, or every caller of a closed function. A condition that
    /// merely mentions the divisor, or a check somewhere else in the file,
    /// proves nothing (ADR-0005).
    fn is_divisor_checked(
        &self,
        div_node: &Node,
        divisor: &Node,
        source: &str,
        env: &TypeEnv,
    ) -> bool {
        // Fast path: compile-time constant expression — evaluate and check non-zero.
        // Covers macros like `BRIGHTNESS_MAX 255`, enum values, and numeric literals.
        {
            let macros = self.file_macros.borrow();
            if let Some(val) = const_eval::try_evaluate_expr(divisor, source, &macros) {
                return val != 0;
            }
        }

        let targets = nonzero_facts::peeled_spellings(divisor, source);
        let facts = nonzero_facts::known_conditions(
            div_node,
            &targets,
            source,
            &self.file_noreturn_names.borrow(),
        );

        // A condition known true or false here that excludes zero for the
        // divisor, an assert before the division, or a `fabs(x) > c` test.
        if self.guarded_nonzero_at(div_node, &targets, &facts, source) {
            return true;
        }

        // Value-range analysis: check if enclosing conditions prove divisor >= 1
        // This catches patterns like `if (lower < upper) { total / (upper - lower); }`
        if self.divisor_provably_nonzero(div_node, divisor, source, env) {
            return true;
        }

        // Guarded-difference divisor: `(A - B)` where a condition known here
        // orders or separates the two operands (`if (high > low)`, an
        // early-return `if (high <= low) return;`, `a != b`). Neither operand
        // needs to be a compile-time constant, only distinct from the other.
        if let Some((a, b)) = Self::extract_diff_operands(divisor, source) {
            let operands = [a.clone(), b.clone()];
            let ordered = facts.iter().any(|(cond, truth)| {
                Self::condition_separates(cond, &a, &b, *truth, source)
                    && nonzero_facts::fact_reaches(cond, div_node, &operands, source)
            });
            if ordered {
                return true;
            }
        }

        // The divisor's last assignment before the division stored a value
        // proven non-zero there: `if (!step) return; p->step = step; x / p->step`.
        if self.assigned_nonzero_before(div_node, &targets, source, env) {
            return true;
        }

        // Check if ALL assignments to the divisor variable in the containing
        // function are provably non-zero constants.  This catches the common
        // Juliet "goodG2B" pattern: `data = -1; data = 7; 100 / data;`
        if divisor.kind() == "identifier" && self.all_assignments_nonzero(div_node, divisor, source)
        {
            return true;
        }

        // A parameter of a closed function every caller passes a value
        // proven non-zero.
        self.every_caller_passes_nonzero(divisor, source, env)
    }

    /// Whether the last plain assignment to one of `targets` at statement
    /// level in a block holding `site` (an earlier statement of it) stores a
    /// value this rule proves non-zero at the assignment, and nothing between
    /// the assignment and `site` writes the divisor again or otherwise
    /// separates the two (`nonzero_facts::fact_reaches`).
    fn assigned_nonzero_before(
        &self,
        site: &Node,
        targets: &[String],
        source: &str,
        env: &TypeEnv,
    ) -> bool {
        let mut current = *site;
        while let Some(parent) = current.parent() {
            if parent.kind() == "function_definition" {
                return false;
            }
            if matches!(parent.kind(), "compound_statement" | "case_statement") {
                let preceding: Vec<Node> = parent
                    .named_child_nodes()
                    .take_while(|stmt| stmt.end_byte() <= current.start_byte())
                    .collect();
                for stmt in preceding.iter().rev() {
                    let Some(assignment) = stmt.named_child(0).filter(|e| {
                        stmt.kind() == "expression_statement" && e.kind() == "assignment_expression"
                    }) else {
                        continue;
                    };
                    let plain = assignment
                        .child_by_field_name("operator")
                        .is_some_and(|op| op.kind() == "=");
                    let assigns_target = assignment.child_by_field_name("left").is_some_and(|l| {
                        targets.contains(&guard_dominance::squeeze_text(&l, source))
                    });
                    if !(plain && assigns_target) {
                        continue;
                    }
                    return nonzero_facts::fact_reaches(&assignment, site, targets, source)
                        && assignment
                            .child_by_field_name("right")
                            .is_some_and(|value| {
                                self.is_divisor_checked(&assignment, &value, source, env)
                            });
                }
            }
            current = parent;
        }
        false
    }

    /// Whether a condition known where the division executes, or an assert
    /// on a statement before it, proves the divisor non-zero.
    ///
    /// `facts` are `nonzero_facts::known_conditions`, so a true `n > 0 && x / n`, a false
    /// `n == 0 || x / n`, the guarded arm of `n ? x / n : 0`, and a preceding
    /// `if (n == 0) return;` all read the same way, and a division in the
    /// zero branch itself (`if (n == 0) { x / n; }`) reads the condition true
    /// and is not credited.
    ///
    /// An assert is credited here on purpose. `guard_dominance` leaves
    /// `assert()` out because it compiles away under `NDEBUG`, but a division
    /// guarded only by `assert(n != 0)` is not what this rule's finding says --
    /// "without checking for zero" -- and a fifth of one corpus's findings were
    /// this shape (valkey). The check compiling out is the assert's
    /// own well-known caveat, not an unguarded division.
    fn guarded_nonzero_at(
        &self,
        div_node: &Node,
        targets: &[String],
        facts: &[(Node, bool)],
        source: &str,
    ) -> bool {
        let macros = self.file_macros.borrow();

        let dominated = facts.iter().any(|(cond, truth)| {
            guard_dominance::condition_excludes_zero(cond, targets, *truth, source, &macros)
                || Self::fabs_excludes_zero(cond, targets, *truth, source)
        });
        if dominated {
            return true;
        }

        let settings = self.settings.borrow();
        let checks = Arc::clone(self.abort_check_macros.borrow().get(&settings));
        let credit = GuardCredit {
            assert_is_guard: settings.flag("assert_is_guard"),
            checks: &checks,
        };
        Self::asserted_nonzero_before(div_node, targets, source, &macros, &credit)
    }

    /// Whether a check statement preceding `site` in one of its enclosing
    /// blocks checks a condition excluding zero for one of `targets`, with no
    /// assignment to that target between the two. Which statements count is
    /// `credit`'s: see [`Self::asserts_nonzero`].
    ///
    /// Same walk as ARR38-C's `asserted_size_bound`: preceding siblings at each
    /// block level up to the function, looking through preprocessor wrappers
    /// because an `assert` under `#ifndef NDEBUG` is a common spelling.
    fn asserted_nonzero_before(
        site: &Node,
        targets: &[String],
        source: &str,
        macros: &MacroConstantMap,
        credit: &GuardCredit,
    ) -> bool {
        const BLOCK_LIKE_KINDS: &[&str] = &[
            "compound_statement",
            "preproc_if",
            "preproc_ifdef",
            "preproc_else",
            "preproc_elif",
        ];

        let mut current = *site;
        while let Some(parent) = current.parent() {
            if BLOCK_LIKE_KINDS.contains(&parent.kind()) {
                let mut cursor = parent.walk();
                let preceding: Vec<Node> = parent
                    .named_children(&mut cursor)
                    .take_while(|stmt| stmt.start_byte() < current.start_byte())
                    .collect();
                for (i, stmt) in preceding.iter().enumerate() {
                    if !Self::asserts_nonzero(stmt, targets, source, macros, credit) {
                        continue;
                    }
                    // Anything assigned to the divisor after the assert and
                    // before the division makes the assert stale.
                    let reassigned = preceding[i + 1..]
                        .iter()
                        .any(|later| Self::assigns_any_of(later, targets, source));
                    if !reassigned && nonzero_facts::fact_reaches(stmt, site, targets, source) {
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

    /// Whether `stmt` checks a condition excluding zero for a target:
    ///
    /// - a check macro no configuration compiles out, recognized by what it
    ///   expands to (`check_macros::abort_checked_argument`, e.g. valkey's
    ///   `serverAssert`), under every policy;
    /// - an assert-named call (`assert`, `DEBUGASSERT`, `WPA_ASSERT`), or one
    ///   inside a preprocessor wrapper, only when the policy credits an
    ///   `NDEBUG`-strippable assert (`assert_is_guard`). The strict policy
    ///   reads the release configuration, where it is gone and the division
    ///   is unchecked (ADR-0010 D5).
    fn asserts_nonzero(
        stmt: &Node,
        targets: &[String],
        source: &str,
        macros: &MacroConstantMap,
        credit: &GuardCredit,
    ) -> bool {
        if let Some(cond) = check_macros::abort_checked_argument(stmt, source, credit.checks) {
            return guard_dominance::condition_excludes_zero(&cond, targets, true, source, macros);
        }
        if !credit.assert_is_guard {
            return false;
        }
        if stmt.kind().starts_with("preproc_") {
            let mut cursor = stmt.walk();
            let mut inner = stmt.named_children(&mut cursor);
            return inner.any(|s| Self::asserts_nonzero(&s, targets, source, macros, credit));
        }
        let call = if stmt.kind() == "expression_statement" {
            match stmt.named_child(0) {
                Some(c) => c,
                None => return false,
            }
        } else {
            *stmt
        };
        if call.kind() != "call_expression" {
            return false;
        }
        let Some(function) = call.child_by_field_name("function") else {
            return false;
        };
        if !ast_utils::get_node_text(&function, source)
            .to_ascii_lowercase()
            .contains("assert")
        {
            return false;
        }
        call.child_by_field_name("arguments")
            .and_then(|args| args.named_child(0))
            .is_some_and(|cond| {
                guard_dominance::condition_excludes_zero(&cond, targets, true, source, macros)
            })
    }

    /// Whether any assignment or `++`/`--` anywhere under `node` writes one
    /// of `targets`, matched on the written expression's squeezed text.
    fn assigns_any_of(node: &Node, targets: &[String], source: &str) -> bool {
        query::find_first_descendant(*node, |n| match n.kind() {
            "assignment_expression" => n
                .child_by_field_name("left")
                .is_some_and(|lhs| targets.contains(&guard_dominance::squeeze_text(&lhs, source))),
            "update_expression" => n
                .child_by_field_name("argument")
                .is_some_and(|arg| targets.contains(&guard_dominance::squeeze_text(&arg, source))),
            _ => false,
        })
        .is_some()
    }

    /// Check if target is a descendant of node (O(1) via byte-range containment)
    fn is_descendant(node: &Node, target: &Node) -> bool {
        target.start_byte() >= node.start_byte() && target.end_byte() <= node.end_byte()
    }

    /// If `divisor` is (optionally parenthesized) a subtraction `A - B`,
    /// return the two operands' whitespace-stripped text. Used to recognize the common
    /// "difference of two bounds" divisor idiom (e.g. `high - low`) so a
    /// relational guard between the operands (rather than a zero-check on
    /// the whole expression) can prove it non-zero.
    fn extract_diff_operands(divisor: &Node, source: &str) -> Option<(String, String)> {
        let inner = if divisor.kind() == "parenthesized_expression" {
            divisor.named_child(0)?
        } else {
            *divisor
        };
        if inner.kind() != "binary_expression" {
            return None;
        }
        if ast_utils::get_binary_operator(&inner, source)? != "-" {
            return None;
        }
        let left = inner.child_by_field_name("left")?;
        let right = inner.child_by_field_name("right")?;
        Some((
            guard_dominance::squeeze_text(&left, source),
            guard_dominance::squeeze_text(&right, source),
        ))
    }

    /// Whether `condition`, known to have evaluated to `known_true`, proves
    /// `a != b`, and so `a - b != 0`: true for `a < b`, `a > b` or `a != b`
    /// (either operand order), false for `a == b`, `a <= b` or `a >= b`. A
    /// true `&&` or a false `||` makes each side a fact, `!` flips the truth,
    /// and parentheses are transparent, as in
    /// `guard_dominance::condition_excludes_zero`.
    fn condition_separates(
        condition: &Node,
        a: &str,
        b: &str,
        known_true: bool,
        source: &str,
    ) -> bool {
        let mut cond = *condition;
        while cond.kind() == "parenthesized_expression" {
            match cond.named_child(0) {
                Some(inner) => cond = inner,
                None => return false,
            }
        }
        match cond.kind() {
            "unary_expression" => {
                let is_not = cond
                    .child_by_field_name("operator")
                    .is_some_and(|o| o.kind() == "!");
                is_not
                    && cond.child_by_field_name("argument").is_some_and(|arg| {
                        Self::condition_separates(&arg, a, b, !known_true, source)
                    })
            }
            "binary_expression" => {
                let Some(op) = cond.child_by_field_name("operator").map(|o| o.kind()) else {
                    return false;
                };
                let (Some(left), Some(right)) = (
                    cond.child_by_field_name("left"),
                    cond.child_by_field_name("right"),
                ) else {
                    return false;
                };
                match op {
                    "&&" | "||" => {
                        (op == "&&") == known_true
                            && (Self::condition_separates(&left, a, b, known_true, source)
                                || Self::condition_separates(&right, a, b, known_true, source))
                    }
                    _ => {
                        let l = guard_dominance::squeeze_text(&left, source);
                        let r = guard_dominance::squeeze_text(&right, source);
                        let operands = (l == a && r == b) || (l == b && r == a);
                        operands
                            && if known_true {
                                matches!(op, "<" | ">" | "!=")
                            } else {
                                matches!(op, "==" | "<=" | ">=")
                            }
                    }
                }
            }
            _ => false,
        }
    }

    /// Use value-range analysis to prove a divisor is provably non-zero.
    ///
    /// First tries CFG-based VRA (if available), which handles sequential
    /// assignments, conditional narrowing through arbitrary paths, and
    /// early-return guard patterns. Falls back to syntactic ancestor walks.
    fn divisor_provably_nonzero(
        &self,
        div_node: &Node,
        divisor: &Node,
        source: &str,
        env: &TypeEnv,
    ) -> bool {
        // Ranges are computed as if arithmetic never wrapped, which an
        // unsigned sum, product or shift does: `d + 1` is zero for
        // `d == UINT_MAX` however surely `d > 0`.
        if self.unsigned_arithmetic_in(divisor, source, env) {
            return false;
        }
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

    /// Whether `expr` holds a `+`, `*` or `<<` computed in an unsigned type,
    /// outside a `sizeof` and short of a constant the file evaluates. `env`
    /// is the file's, from [`CertRule::check`]: one built here would index
    /// the whole tree again for every divisor.
    fn unsigned_arithmetic_in(&self, expr: &Node, source: &str, env: &TypeEnv) -> bool {
        let macros = self.file_macros.borrow();
        let mut stack = vec![*expr];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "sizeof_expression" | "alignof_expression" => continue,
                "binary_expression" => {
                    let wraps = ast_utils::get_binary_operator(&node, source)
                        .is_some_and(|op| matches!(op, "+" | "*" | "<<"))
                        && const_eval::try_evaluate_expr(&node, source, &macros).is_none()
                        && expr_type::expr_type(&node, source, env).and_then(|t| t.is_unsigned())
                            == Some(true);
                    if wraps {
                        return true;
                    }
                }
                _ => {}
            }
            stack.extend(node.named_child_nodes());
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

    /// Whether a `fabs(x) > c` test with `c >= 0`, known to have the given
    /// truth value, proves `x` non-zero for some `x` in `targets`. A true
    /// `&&` or a false `||` makes each side a fact, `!` flips the truth.
    fn fabs_excludes_zero(
        condition: &Node,
        targets: &[String],
        known_true: bool,
        source: &str,
    ) -> bool {
        let mut cond = *condition;
        while cond.kind() == "parenthesized_expression" {
            match cond.named_child(0) {
                Some(inner) => cond = inner,
                None => return false,
            }
        }
        match cond.kind() {
            "unary_expression" => {
                cond.child_by_field_name("operator")
                    .is_some_and(|o| o.kind() == "!")
                    && cond.child_by_field_name("argument").is_some_and(|arg| {
                        Self::fabs_excludes_zero(&arg, targets, !known_true, source)
                    })
            }
            "binary_expression" => {
                let Some(op) = cond.child_by_field_name("operator").map(|o| o.kind()) else {
                    return false;
                };
                let (Some(left), Some(right)) = (
                    cond.child_by_field_name("left"),
                    cond.child_by_field_name("right"),
                ) else {
                    return false;
                };
                match op {
                    "&&" | "||" => {
                        (op == "&&") == known_true
                            && (Self::fabs_excludes_zero(&left, targets, known_true, source)
                                || Self::fabs_excludes_zero(&right, targets, known_true, source))
                    }
                    // `fabs(x) > c` holds, or `fabs(x) <= c` fails.
                    ">" | "<=" if (op == ">") == known_true => {
                        let is_fabs_of_target = left.kind() == "call_expression"
                            && left.child_by_field_name("function").is_some_and(|f| {
                                matches!(
                                    ast_utils::get_node_text(&f, source),
                                    "fabs" | "fabsf" | "fabsl"
                                )
                            })
                            && left
                                .child_by_field_name("arguments")
                                .filter(|args| args.named_child_count() == 1)
                                .and_then(|args| args.named_child(0))
                                .is_some_and(|arg| {
                                    targets.contains(&guard_dominance::squeeze_text(&arg, source))
                                });
                        is_fabs_of_target
                            && Self::try_parse_float_literal(&right, source)
                                .is_some_and(|c| c >= 0.0)
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// Whether `divisor` is a parameter of a function every call of which
    /// passes, at that position, a value proven non-zero at the call the way
    /// this rule proves a divisor non-zero ([`Self::is_divisor_checked`]).
    ///
    /// The caller set must be closed (ADR-0011): the function is defined in
    /// the `.c` file being checked and has internal linkage, so every call
    /// is in this translation unit -- a `static` function in a header has
    /// another set of callers in every file including it -- and its name is
    /// used nowhere but as the callee of a direct call and in its own
    /// declarators -- not stored, passed, or named in a macro, through which
    /// it could be called by code that does not name it. There must be at
    /// least one call, and nothing in the function may write the parameter.
    /// A caller forwarding its own parameter is judged the same way in turn;
    /// a cycle proves nothing.
    fn every_caller_passes_nonzero(&self, divisor: &Node, source: &str, env: &TypeEnv) -> bool {
        let mut param = *divisor;
        while let Some(inner) = nonzero_facts::peel_sign(&param) {
            param = inner;
        }
        if param.kind() != "identifier" {
            return false;
        }
        let name = ast_utils::get_node_text(&param, source);
        if !matches!(
            ast_utils::resolve_identifier_binding(&param, name, source),
            Some(ast_utils::IdentifierBinding::Parameter(_))
        ) {
            return false;
        }
        let Some(func) = ast_utils::find_containing_function(&param) else {
            return false;
        };
        let Some(index) = ast_utils::get_function_parameters(&func, source)
            .and_then(|params| params.iter().position(|(n, _)| n == name))
        else {
            return false;
        };
        let key = (func.start_byte(), index);
        if let Some(&known) = self.caller_proofs.borrow().get(&key) {
            return known;
        }
        // Provisionally unproven, so a call cycle back to here proves nothing.
        self.caller_proofs.borrow_mut().insert(key, false);
        let proven = self.callers_pass_nonzero(&func, name, index, source, env);
        self.caller_proofs.borrow_mut().insert(key, proven);
        proven
    }

    /// The body of [`Self::every_caller_passes_nonzero`] for parameter
    /// `index`, named `param`, of `func`.
    fn callers_pass_nonzero(
        &self,
        func: &Node,
        param: &str,
        index: usize,
        source: &str,
        env: &TypeEnv,
    ) -> bool {
        let Some(body) = func.child_by_field_name("body") else {
            return false;
        };
        let names = [param.to_string()];
        if Self::assigns_any_of(&body, &names, source)
            || Self::takes_address_of(&body, param, source)
        {
            return false;
        }
        let in_c_file = self
            .file_path
            .borrow()
            .as_ref()
            .and_then(|p| p.extension())
            .is_some_and(|ext| ext == "c");
        if !in_c_file {
            return false;
        }
        let Some(fname) = lang_parsing_substrate::calls::get_function_name(*func, source) else {
            return false;
        };
        let mut root = *func;
        while let Some(parent) = root.parent() {
            root = parent;
        }
        if !Self::has_internal_linkage(&root, &fname, source) {
            return false;
        }

        let mut calls = Vec::new();
        for ident in query::find_descendants_of_kind(root, "identifier") {
            if ast_utils::get_node_text(&ident, source) != fname {
                continue;
            }
            let Some(parent) = ident.parent() else {
                return false;
            };
            let is_field = |field: &str| {
                parent
                    .child_by_field_name(field)
                    .is_some_and(|n| n.id() == ident.id())
            };
            match parent.kind() {
                "call_expression" if is_field("function") => calls.push(parent),
                "function_declarator" if is_field("declarator") => {}
                _ => return false,
            }
        }
        // A macro naming the function can call it, or take its address,
        // wherever it is expanded.
        let in_macro = query::find_first_descendant(root, |n| {
            matches!(n.kind(), "preproc_def" | "preproc_function_def")
                && n.child_by_field_name("value").is_some_and(|v| {
                    ast_utils::get_node_text(&v, source)
                        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                        .any(|word| word == fname)
                })
        });
        if in_macro.is_some() || calls.is_empty() {
            return false;
        }
        calls.iter().all(|call| {
            call.child_by_field_name("arguments")
                .and_then(|args| {
                    args.named_child_nodes()
                        .filter(|a| a.kind() != "comment")
                        .nth(index)
                })
                .is_some_and(|arg| self.is_divisor_checked(call, &arg, source, env))
        })
    }

    /// Whether `&name` appears anywhere under `node`.
    fn takes_address_of(node: &Node, name: &str, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            n.kind() == "pointer_expression"
                && n.child_by_field_name("operator")
                    .is_some_and(|op| op.kind() == "&")
                && n.child_by_field_name("argument")
                    .is_some_and(|arg| guard_dominance::squeeze_text(&arg, source) == name)
        })
        .is_some()
    }

    /// Whether some file-scope declaration or definition of function `name`
    /// in the translation unit under `root` says `static`, which gives every
    /// declaration of it internal linkage (C11 6.2.2p3, p5).
    fn has_internal_linkage(root: &Node, name: &str, source: &str) -> bool {
        let names_it = |decl: &Node| {
            query::find_first_descendant(*decl, |n| {
                n.kind() == "function_declarator"
                    && n.child_by_field_name("declarator").is_some_and(|d| {
                        d.kind() == "identifier" && ast_utils::get_node_text(&d, source) == name
                    })
            })
            .is_some()
        };
        let is_static = |decl: &Node| {
            decl.named_child_nodes().any(|c| {
                c.kind() == "storage_class_specifier"
                    && ast_utils::get_node_text(&c, source) == "static"
            })
        };
        let mut stack = vec![*root];
        while let Some(scope) = stack.pop() {
            for item in scope.named_child_nodes() {
                match item.kind() {
                    "function_definition" | "declaration"
                        if is_static(&item) && names_it(&item) =>
                    {
                        return true;
                    }
                    kind if kind.starts_with("preproc_") => stack.push(item),
                    _ => {}
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
                            // A bound holds only while nothing since the
                            // condition changed what it bounds.
                            let names: Vec<String> =
                                query::find_descendants_of_kind(condition, "identifier")
                                    .iter()
                                    .map(|i| ast_utils::get_node_text(i, source).to_string())
                                    .collect();
                            if nonzero_facts::fact_reaches(&condition, node, &names, source) {
                                Self::extract_comparison_bounds(&condition, source, macros, ranges);
                            }
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

    /// Check if ALL assignments to the local variable `divisor` names in the
    /// containing function are provably non-zero constants. False if any
    /// assignment is unknown or zero, if its address is taken (a callee may
    /// store anything through it), or if it is not a local of this function:
    /// a parameter or a global holds a value no assignment here set when
    /// the path assigning it is not taken.
    fn all_assignments_nonzero(&self, div_node: &Node, divisor: &Node, source: &str) -> bool {
        let var_name = ast_utils::get_node_text(divisor, source);
        if !matches!(
            ast_utils::resolve_identifier_binding(divisor, var_name, source),
            Some(ast_utils::IdentifierBinding::Local(_))
        ) {
            return false;
        }
        let func = match ast_utils::find_containing_function(div_node) {
            Some(f) => f,
            None => return false,
        };
        let body = match func.child_by_field_name("body") {
            Some(b) => b,
            None => return false,
        };
        if Self::takes_address_of(&body, var_name, source) {
            return false;
        }
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
        // A declaration with no initializer and no assignment proves nothing.
        found_any
    }

    /// Walk `scope` collecting assignments to `var_name`.
    /// Returns false immediately if any assignment is zero or non-constant.
    ///
    /// Uses an explicit stack instead of recursion: the catch-all `_` arm
    /// below descends into every unmatched child kind (if/while/compound/
    /// etc.), so a pathologically nested if/else-if or block chain could
    /// blow the native call stack one frame per level (the same hostap-
    /// style shape that motivated an earlier fix). `found_any` is write-only
    /// (set true, never cleared) and any bad assignment aborts the whole
    /// walk immediately, so processing children out of document order via
    /// the stack doesn't change the result.
    fn collect_assignments_all_nonzero(
        scope: &Node,
        var_name: &str,
        source: &str,
        macros: &MacroConstantMap,
        found_any: &mut bool,
    ) -> bool {
        let mut stack = vec![*scope];

        while let Some(cur_scope) = stack.pop() {
            for child in cur_scope.named_child_nodes() {
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
                        // Still queue the for body
                        stack.push(child);
                    }
                    _ => {
                        // Queue compound statements, if-bodies, etc.
                        stack.push(child);
                    }
                }
            }
        }
        true
    }

    /// Check if `node` contains an update expression (++, --, +=, -=, etc.)
    /// that modifies `var_name`. Returns true if found.
    fn is_variable_modified_by_update(node: &Node, var_name: &str, source: &str) -> bool {
        query::find_first_descendant(*node, |n| match n.kind() {
            "update_expression" => {
                // i++, i--, ++i, --i
                let text = ast_utils::get_node_text(&n, source);
                text.contains(var_name)
            }
            "assignment_expression" => {
                // Check for compound assignments (+=, -=, *=, /=, etc.)
                if let Some(lhs) = n.child_by_field_name("left") {
                    if lhs.kind() == "identifier"
                        && ast_utils::get_node_text(&lhs, source) == var_name
                    {
                        let full_text = ast_utils::get_node_text(&n, source);
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
            _ => false,
        })
        .is_some()
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
        for child in decl.named_child_nodes() {
            if child.kind() == "init_declarator" {
                // Look for the identifier
                for gc in child.named_child_nodes() {
                    if gc.kind() == "identifier"
                        && ast_utils::get_node_text(&gc, source) == var_name
                    {
                        return true;
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
        for child in decl.named_child_nodes() {
            if child.kind() == "init_declarator" {
                let mut found_name = false;
                let mut value_node = None;
                for gc in child.named_child_nodes() {
                    if gc.kind() == "identifier"
                        && ast_utils::get_node_text(&gc, source) == var_name
                    {
                        found_name = true;
                    } else if found_name && gc.kind() != "=" {
                        value_node = Some(gc);
                        break;
                    }
                }
                if found_name {
                    return value_node;
                }
            }
        }
        None
    }

    // ---- Floating-point operand typing (INT33-C applies only to integer div) ----

    /// True if the division/remainder operation `node` has at least one
    /// float-typed operand, making it a floating-point operation (FLP03-C's
    /// concern for a zero divisor) rather than the integer divide-by-zero
    /// INT33-C covers.
    fn division_is_floating(&self, node: &Node, source: &str, env: &TypeEnv) -> bool {
        ["left", "right"].iter().any(|f| {
            node.child_by_field_name(f)
                .is_some_and(|n| float_typing::expr_is_float(&n, source, env))
        })
    }
}
