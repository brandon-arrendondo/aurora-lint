//! FLP03-C: Detect and handle floating-point errors
//!
//! This rule addresses the detection and handling of errors occurring during
//! floating-point operations. Programmers often validate operands before operations
//! but neglect errors that occur during computation itself, which can result in
//! silent failures and unexpected arithmetic results.
//!
//! ## Floating-Point Errors to Detect:
//! - **Divide-by-zero**: Returns infinity rather than aborting
//! - **Inexact operations**: Loss of precision
//! - **Underflow**: Results too small to represent
//! - **Overflow**: Results too large for the data type
//! - **Invalid operations**: Conversions causing undefined values
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void fpOper_noErrorChecking(void) {
//!     double a = 1e-40, b, c = 0.1;
//!     float x = 0, y;
//!     y = a;           // Inexact and underflows - no error check
//!     b = y / x;       // Divide-by-zero - no error check
//!     c = sin(30) * a; // Inexact - no error check
//! }
//! ```
//!
//! **Compliant (using fenv.h):**
//! ```c
//! #include <fenv.h>
//! #pragma STDC FENV_ACCESS ON
//!
//! void fpOper_fenv(void) {
//!     double a = 1e-40, b, c = 0.1;
//!     float x = 0, y;
//!     int fpeRaised;
//!
//!     feclearexcept(FE_ALL_EXCEPT);
//!     y = a;
//!     fpeRaised = fetestexcept(FE_ALL_EXCEPT);
//!
//!     feclearexcept(FE_ALL_EXCEPT);
//!     b = y / x;
//!     fpeRaised = fetestexcept(FE_ALL_EXCEPT);
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Flp03C;

/// Analyzer that tracks floating-point variables
struct FpAnalyzer {
    float_vars: HashSet<String>,
}

impl FpAnalyzer {
    fn new() -> Self {
        Self {
            float_vars: HashSet::new(),
        }
    }

    /// Collect all floating-point variable declarations from the AST
    fn collect_float_vars(&mut self, node: &Node, source: &str) {
        for decl in query::find_descendants_of_kind(*node, "declaration") {
            let decl_text = get_node_text(&decl, source);
            // Check if this is a float/double declaration
            if decl_text.starts_with("float")
                || decl_text.starts_with("double")
                || decl_text.contains(" float ")
                || decl_text.contains(" double ")
            {
                // Extract all identifiers from this declaration
                self.extract_identifiers_from_declaration(&decl, source);
            }
        }
    }

    fn extract_identifiers_from_declaration(&mut self, node: &Node, source: &str) {
        // Look for init_declarator or declarator nodes containing identifiers
        for id_node in query::find_descendants_of_kind(*node, "identifier") {
            // Verify parent is a declarator-type node (not type specifier)
            if let Some(parent) = id_node.parent() {
                let parent_kind = parent.kind();
                if parent_kind == "init_declarator"
                    || parent_kind == "declarator"
                    || parent_kind == "pointer_declarator"
                    || parent_kind == "array_declarator"
                {
                    let var_name = get_node_text(&id_node, source).to_string();
                    self.float_vars.insert(var_name);
                }
            }
        }
    }

    /// Check if an expression involves floating-point values or variables
    fn is_fp_expression(&self, node: &Node, source: &str) -> bool {
        let text = get_node_text(node, source);

        // Check for floating-point literals (contains decimal point or e notation)
        if text.contains('.') && !text.starts_with("/*") {
            return true;
        }

        // Precise scientific notation: digit before e/E, digit or sign after
        // Avoids matching 'e' in identifiers like "sizeof"
        let bytes = text.as_bytes();
        for i in 1..bytes.len().saturating_sub(1) {
            if bytes[i] == b'e' || bytes[i] == b'E' {
                let before = bytes[i - 1];
                let after = bytes[i + 1];
                if before.is_ascii_digit()
                    && (after.is_ascii_digit() || after == b'+' || after == b'-')
                {
                    return true;
                }
            }
        }

        // Check for floating-point type keywords
        if text.contains("float") || text.contains("double") {
            return true;
        }

        // Check if any identifier in this expression is a known float variable
        self.contains_float_identifier(node, source)
    }

    fn contains_float_identifier(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            n.kind() == "identifier" && self.float_vars.contains(get_node_text(&n, source))
        })
        .is_some()
    }
}

impl Flp03C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self
    }

    /// List of floating-point error checking functions from fenv.h
    const FENV_FUNCTIONS: &'static [&'static str] = &[
        "feclearexcept",
        "fetestexcept",
        "fegetexceptflag",
        "fesetexceptflag",
        "feraiseexcept",
    ];

    /// List of Windows-specific floating-point error checking functions
    const WINDOWS_FP_FUNCTIONS: &'static [&'static str] =
        &["_clearfp", "_statusfp", "_controlfp", "_fpieee_flt"];

    /// Check if a function name is a floating-point error checking function
    fn is_fp_error_check_function(&self, name: &str) -> bool {
        Self::FENV_FUNCTIONS.contains(&name) || Self::WINDOWS_FP_FUNCTIONS.contains(&name)
    }

    /// Check if a node contains floating-point error checking calls
    fn contains_fp_error_checking(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            // Check this node
            if n.kind() == "call_expression" {
                if let Some(function) = n.child_by_field_name("function") {
                    let func_name = get_node_text(&function, source);
                    if self.is_fp_error_check_function(func_name) {
                        return true;
                    }
                }
            }

            // Check for Windows SEH exception handling (_try/_except or __try/__except)
            // These are typically parsed as identifier nodes with the text "_try", "__try", etc.
            let node_text = get_node_text(&n, source);
            if node_text.contains("_try")
                || node_text.contains("__try")
                || node_text.contains("_except")
                || node_text.contains("__except")
            {
                return true;
            }

            // Also check for _fpieee_flt which is Windows FP exception handling
            if node_text.contains("_fpieee_flt") || node_text.contains("unmask_fpsr") {
                return true;
            }

            false
        })
        .is_some()
    }

    /// Check for floating-point division operations
    fn check_fp_division(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        analyzer: &FpAnalyzer,
    ) {
        if node.kind() == "binary_expression" {
            // Check if this is a division operation
            let mut is_division = false;
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "/" {
                        is_division = true;
                        break;
                    }
                }
            }

            // Check each operand individually — at least one must be float
            let left_fp = node
                .child_by_field_name("left")
                .is_some_and(|l| analyzer.is_fp_expression(&l, source));
            let right_fp = node
                .child_by_field_name("right")
                .is_some_and(|r| analyzer.is_fp_expression(&r, source));
            if is_division && (left_fp || right_fp) {
                // Check if the division is inside a divide-by-zero guard
                if self.is_inside_division_guard(node, source) {
                    return;
                }

                // Check if the divisor is provably non-zero (all assignments
                // to it are non-zero constants). Catches goodG2B pattern:
                // `data = 2.0F; 100.0 / data;`
                if let Some(right) = node.child_by_field_name("right") {
                    if right.kind() == "identifier" {
                        let var_name = get_node_text(&right, source);
                        if Self::divisor_provably_nonzero_fp(node, var_name, source) {
                            return;
                        }
                    }
                }

                // Check if there's error checking in the containing function
                if let Some(containing_func) = self.find_containing_function(node) {
                    if !self.contains_fp_error_checking(&containing_func, source) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: "Floating-point division without error checking (consider using feclearexcept/fetestexcept)".to_string(),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(
                                "Use feclearexcept(FE_ALL_EXCEPT) before and fetestexcept(FE_ALL_EXCEPT) after floating-point operations".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Find the containing function definition for a given node
    fn find_containing_function<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = Some(*node);
        while let Some(n) = current {
            if n.kind() == "function_definition" {
                return Some(n);
            }
            current = n.parent();
        }
        None
    }

    /// Check if a division node is inside a guard that protects against divide-by-zero.
    /// Recognizes patterns like:
    /// - `if (fabs(data) > 0.000001)` (magnitude check)
    /// - `if (data != 0)` or `if (data != 0.0)` (zero check)
    /// - `if (x > 0)` / `if (x < 0)` (sign check implies non-zero)
    fn is_inside_division_guard(&self, node: &Node, source: &str) -> bool {
        let mut current = node.parent();
        // Walk up to 15 ancestors looking for an enclosing if_statement
        let mut depth = 0;
        while let Some(n) = current {
            if depth > 15 {
                break;
            }
            if n.kind() == "if_statement" {
                if let Some(condition) = n.child_by_field_name("condition") {
                    let cond_text = get_node_text(&condition, source);
                    if Self::is_division_guard_condition(&cond_text) {
                        return true;
                    }
                }
            }
            current = n.parent();
            depth += 1;
        }
        false
    }

    /// Check if a condition text represents a divide-by-zero guard.
    fn is_division_guard_condition(cond_text: &str) -> bool {
        // fabs/fabsf/fabsl magnitude checks: fabs(x) > threshold
        if cond_text.contains("fabs") || cond_text.contains("fabsf") || cond_text.contains("fabsl")
        {
            if cond_text.contains('>') {
                return true;
            }
        }

        // != 0 or != 0.0 checks
        if (cond_text.contains("!= 0") || cond_text.contains("!=0")) && !cond_text.contains("== 0")
        {
            return true;
        }

        // Comparisons against zero that imply non-zero: > 0, < 0
        // But not >= 0 or <= 0 (those don't exclude zero)
        if (cond_text.contains("> 0") || cond_text.contains(">0"))
            && !cond_text.contains(">= 0")
            && !cond_text.contains(">=0")
        {
            return true;
        }
        if (cond_text.contains("< 0") || cond_text.contains("<0"))
            && !cond_text.contains("<= 0")
            && !cond_text.contains("<=0")
        {
            return true;
        }

        false
    }

    /// Check if the divisor variable is provably non-zero at the division point.
    /// Two strategies:
    /// 1. ALL assignments in the function are non-zero constants (catches `data=-1; data=7;`)
    /// 2. Constant-aware walk: track last assignment through feasible branches,
    ///    using file-scope constants to prune dead code (catches branched patterns
    ///    like `data=0.0F; if(STATIC_CONST_TRUE) { data=2.0F; } use(data);`)
    fn divisor_provably_nonzero_fp(div_node: &Node, var_name: &str, source: &str) -> bool {
        // Find containing function and translation unit root
        let mut current = Some(*div_node);
        let func = loop {
            match current {
                Some(n) if n.kind() == "function_definition" => break n,
                Some(n) => current = n.parent(),
                None => return false,
            }
        };
        let body = match func.child_by_field_name("body") {
            Some(b) => b,
            None => return false,
        };

        // Strategy 1: all assignments are non-zero
        let mut all_nonzero = true;
        let mut found_any = false;
        Self::check_all_assignments(&body, var_name, source, &mut all_nonzero, &mut found_any);
        if found_any && all_nonzero {
            return true;
        }

        // Strategy 2: constant-aware walk
        // Collect file-scope constants for condition resolution
        let root = {
            let mut n = func;
            while let Some(p) = n.parent() {
                n = p;
            }
            n
        };
        let constants = const_eval::collect_macro_constants(&root, source);
        let div_line = div_node.start_position().row;
        let last_val =
            Self::walk_scope_for_last_assignment(&body, var_name, source, div_line, &constants);
        if last_val == Some(true) {
            return true;
        }

        false
    }

    /// Walk a scope tracking the last assignment to `var_name` before `div_line`.
    /// For if-statements with constant conditions, only follows the feasible branch.
    /// Returns Some(true) if last reaching assignment is non-zero, Some(false) if zero,
    /// None if no assignment found.
    ///
    /// Uses an explicit continuation-frame stack instead of recursion: this
    /// prunes by branch feasibility rather than node kind, so it can't be
    /// mechanically flattened via a generic descendant query, and a long
    /// chain of feasible nested ifs/compounds would cost one native call
    /// frame per level (the same hostap-style risk class as the original
    /// ARR00-C/MEM33-C bug, task 153). Each frame owns its scope's local
    /// `last_val` accumulator; when a frame's scan finishes, its `last_val`
    /// becomes the "return value" applied to the resuming parent frame --
    /// mirroring `if let Some(v) = recursive_call() { last_val = Some(v); }`
    /// exactly, just via an explicit `pending_return` slot instead of the
    /// native call stack.
    fn walk_scope_for_last_assignment(
        scope: &Node,
        var_name: &str,
        source: &str,
        div_line: usize,
        constants: &const_eval::MacroConstantMap,
    ) -> Option<bool> {
        struct Frame<'a> {
            scope: Node<'a>,
            idx: usize,
            last_val: Option<bool>,
        }

        let mut stack: Vec<Frame> = vec![Frame {
            scope: *scope,
            idx: 0,
            last_val: None,
        }];
        // Return value of the most recently completed child frame, to be
        // applied to whichever frame resumes next.
        let mut pending_return: Option<Option<bool>> = None;

        loop {
            let mut frame = stack.pop().expect("stack non-empty by loop invariant");

            if let Some(Some(v)) = pending_return.take() {
                frame.last_val = Some(v);
            }

            let mut spawned: Option<Frame> = None;
            while frame.idx < frame.scope.named_child_count() {
                let child = match frame.scope.named_child(frame.idx) {
                    Some(c) => c,
                    None => {
                        frame.idx += 1;
                        continue;
                    }
                };
                if child.start_position().row >= div_line {
                    break;
                }
                // Direct assignment
                if let Some(is_nz) = Self::get_assignment_value(&child, var_name, source) {
                    frame.last_val = Some(is_nz);
                    frame.idx += 1;
                    continue;
                }
                // If-statement: resolve condition if possible
                if child.kind() == "if_statement" {
                    let mut target = None;
                    if let Some(cond) = child.child_by_field_name("condition") {
                        match Self::eval_condition_const(&cond, source, constants) {
                            Some(true) => {
                                // Only then-branch is feasible
                                target = child.child_by_field_name("consequence");
                            }
                            Some(false) => {
                                // Only else-branch is feasible
                                target = child.child_by_field_name("alternative");
                            }
                            None => {
                                // Unknown condition: conservatively don't update
                                // last_val (both branches are possible, can't
                                // guarantee which)
                            }
                        }
                    }
                    frame.idx += 1;
                    if let Some(target) = target {
                        spawned = Some(Frame {
                            scope: target,
                            idx: 0,
                            last_val: None,
                        });
                        break;
                    }
                    continue;
                }
                // Recurse into compound statements
                if child.kind() == "compound_statement" {
                    frame.idx += 1;
                    spawned = Some(Frame {
                        scope: child,
                        idx: 0,
                        last_val: None,
                    });
                    break;
                }
                frame.idx += 1;
            }

            if let Some(child_frame) = spawned {
                stack.push(frame);
                stack.push(child_frame);
                continue;
            }

            if stack.is_empty() {
                return frame.last_val;
            }
            pending_return = Some(frame.last_val);
        }
    }

    /// Evaluate an if-condition as a constant boolean, using file-scope constants.
    fn eval_condition_const(
        cond: &Node,
        source: &str,
        constants: &const_eval::MacroConstantMap,
    ) -> Option<bool> {
        // Unwrap parenthesized_expression
        let inner = if cond.kind() == "parenthesized_expression" {
            cond.named_child(0).unwrap_or(*cond)
        } else {
            *cond
        };
        match inner.kind() {
            "number_literal" => {
                let text = get_node_text(&inner, source);
                text.parse::<i64>().ok().map(|n| n != 0)
            }
            "identifier" => {
                let name = get_node_text(&inner, source);
                constants.get(name).map(|&v| v != 0)
            }
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        }
    }

    /// Walk all assignments to var_name, tracking if all are non-zero.
    ///
    /// Uses an explicit stack instead of recursion: unlike
    /// [`Self::walk_scope_for_last_assignment`], this has no branch-value
    /// return dependency (it only accumulates into the shared `&mut`
    /// flags), so a plain node stack suffices -- same unbounded-depth risk
    /// class as the original ARR00-C/MEM33-C bug (task 153).
    fn check_all_assignments(
        scope: &Node,
        var_name: &str,
        source: &str,
        all_nonzero: &mut bool,
        found_any: &mut bool,
    ) {
        let mut stack = vec![*scope];
        while let Some(scope) = stack.pop() {
            for i in (0..scope.named_child_count()).rev() {
                let child = match scope.named_child(i) {
                    Some(c) => c,
                    None => continue,
                };
                if let Some(is_nz) = Self::get_assignment_value(&child, var_name, source) {
                    *found_any = true;
                    if !is_nz {
                        *all_nonzero = false;
                    }
                } else {
                    stack.push(child);
                }
            }
        }
    }

    /// If `node` is a declaration or assignment to `var_name`, return Some(is_nonzero).
    fn get_assignment_value(node: &Node, var_name: &str, source: &str) -> Option<bool> {
        match node.kind() {
            "declaration" => {
                for j in 0..node.named_child_count() {
                    if let Some(gc) = node.named_child(j) {
                        if gc.kind() == "init_declarator" {
                            // Check if it's our variable
                            let has_var = (0..gc.named_child_count()).any(|k| {
                                gc.named_child(k).is_some_and(|n| {
                                    n.kind() == "identifier"
                                        && get_node_text(&n, source) == var_name
                                })
                            });
                            if has_var {
                                if let Some(val) = gc.named_child(gc.named_child_count() - 1) {
                                    if val.kind() != "identifier"
                                        || get_node_text(&val, source) != var_name
                                    {
                                        return Some(Self::is_nonzero_literal(&val, source));
                                    }
                                }
                            }
                        }
                    }
                }
                None
            }
            "expression_statement" => {
                let expr = node.named_child(0)?;
                if expr.kind() != "assignment_expression" {
                    return None;
                }
                let lhs = expr.child_by_field_name("left")?;
                if lhs.kind() == "identifier" && get_node_text(&lhs, source) == var_name {
                    let rhs = expr.child_by_field_name("right")?;
                    return Some(Self::is_nonzero_literal(&rhs, source));
                }
                None
            }
            _ => None,
        }
    }

    /// Check if a node is a non-zero numeric literal (int or float).
    fn is_nonzero_literal(node: &Node, source: &str) -> bool {
        match node.kind() {
            "number_literal" => {
                let text = get_node_text(node, source)
                    .trim_end_matches('f')
                    .trim_end_matches('F')
                    .trim_end_matches('l')
                    .trim_end_matches('L')
                    .to_string();
                if let Ok(v) = text.parse::<f64>() {
                    return v != 0.0;
                }
                if let Ok(v) = text.parse::<i64>() {
                    return v != 0;
                }
                false
            }
            "unary_expression" => {
                // Handle -(literal)
                if let Some(arg) = node.child_by_field_name("argument") {
                    Self::is_nonzero_literal(&arg, source)
                } else {
                    false
                }
            }
            "parenthesized_expression" => {
                if let Some(inner) = node.named_child(0) {
                    Self::is_nonzero_literal(&inner, source)
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}

impl CertRule for Flp03C {
    fn rule_id(&self) -> &'static str {
        "FLP03-C"
    }

    fn description(&self) -> &'static str {
        "Detect and handle floating-point errors"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "FLP03-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: collect all floating-point variable declarations
        let mut analyzer = FpAnalyzer::new();
        analyzer.collect_float_vars(node, source);

        // Second pass: check for violations
        self.check_node(node, source, &mut violations, &analyzer);
        violations
    }
}

impl Flp03C {
    fn check_node(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        analyzer: &FpAnalyzer,
    ) {
        // Check for floating-point division without error checking
        for binary_expr in query::find_descendants_of_kind(*node, "binary_expression") {
            self.check_fp_division(&binary_expr, source, violations, analyzer);
        }
    }
}
