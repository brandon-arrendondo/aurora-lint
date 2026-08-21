//! INT14-C: Avoid performing bitwise and arithmetic operations on the same data
//!
//! This rule addresses performing bitwise and arithmetic operations on the same data.
//! Bitwise operations are frequently used on arithmetic values as premature optimization,
//! which reduces code readability and obscures programmer intent.
//!
//! ## Bitwise operators:
//! - Unary: `~` (bitwise NOT)
//! - Binary: `<<` `>>` (shift), `&` `|` `^` (bitwise AND/OR/XOR)
//!
//! ## Non-compliant examples:
//!
//! **Left shift misuse:**
//! ```c
//! int compute(int x) {
//!     int y = x << 2;  // Bitwise shift
//!     x += y + 1;      // Arithmetic operation
//!     return x;        // Computes 5x + 1 via bit manipulation
//! }
//! ```
//!
//! **Right shift division:**
//! ```c
//! int compute(int x) {
//!     x >>= 2;  // Bitwise shift (implementation-dependent for negatives)
//!     return x; // Attempts division by 4
//! }
//! ```
//!
//! ## Compliant solutions:
//! ```c
//! int compute(int x) {
//!     return 5 * x + 1;  // Clear mathematical intent
//! }
//!
//! int compute(int x) {
//!     return x / 4;  // Explicit division
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Int14C;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum OperationType {
    Bitwise,
    Arithmetic,
}

impl Int14C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self
    }

    /// Check if an operator is a bitwise operator
    fn is_bitwise_operator(&self, op: &str) -> bool {
        matches!(op, "~" | "<<" | ">>" | "&" | "|" | "^")
    }

    /// Check if an operator is an arithmetic operator
    fn is_arithmetic_operator(&self, op: &str) -> bool {
        matches!(op, "+" | "-" | "*" | "/" | "%")
    }

    /// Check if an operator is a shift operator (subset of bitwise often misused for arithmetic)
    fn is_shift_operator(&self, op: &str) -> bool {
        matches!(op, "<<" | ">>" | "<<=" | ">>=")
    }

    /// Collect signed integer parameters from a function
    fn collect_signed_int_params(&self, node: &Node, source: &str) -> HashSet<String> {
        let mut params = HashSet::new();

        // Look for function_declarator within function_definition
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "function_declarator" {
                    self.collect_params_from_declarator(&child, source, &mut params);
                }
            }
        }
        params
    }

    fn collect_params_from_declarator(
        &self,
        node: &Node,
        source: &str,
        params: &mut HashSet<String>,
    ) {
        // Look for parameter_list
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "parameter_list" {
                    self.collect_params_from_list(&child, source, params);
                }
            }
        }
    }

    fn collect_params_from_list(&self, node: &Node, source: &str, params: &mut HashSet<String>) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "parameter_declaration" {
                    let param_text = get_node_text(&child, source);
                    // Check for signed integer types (int, short, long, signed)
                    // Exclude unsigned types
                    if (param_text.contains("int")
                        || param_text.contains("short")
                        || param_text.contains("long"))
                        && !param_text.contains("unsigned")
                    {
                        // Extract parameter name
                        if let Some(name) = self.extract_param_name(&child, source) {
                            params.insert(name);
                        }
                    }
                }
            }
        }
    }

    /// `node` is a `parameter_declaration`. Its declarator may itself be a
    /// bare identifier (simple params) or a pointer/array/function/
    /// parenthesized declarator wrapping one (e.g. `int *x`) -- unwrap via
    /// the shared resolver instead of only checking direct children, which
    /// would silently miss every pointer/array-typed parameter.
    fn extract_param_name(&self, node: &Node, source: &str) -> Option<String> {
        let declarator = node.child_by_field_name("declarator").unwrap_or(*node);
        let name = ast_utils::get_identifier_from_declarator(&declarator, source);
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    /// Extract variable names used in an expression
    fn extract_variables(node: &Node, source: &str, vars: &mut HashSet<String>) {
        for n in query::find_descendants_of_kind(*node, "identifier") {
            vars.insert(get_node_text(&n, source).to_string());
        }
    }

    /// Get the operator from a binary expression
    fn get_operator(&self, node: &Node, source: &str) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let kind = child.kind();
                if kind == "+"
                    || kind == "-"
                    || kind == "*"
                    || kind == "/"
                    || kind == "%"
                    || kind == "<<"
                    || kind == ">>"
                    || kind == "&"
                    || kind == "|"
                    || kind == "^"
                {
                    return Some(kind.to_string());
                }
                // Handle named operators
                let text = get_node_text(&child, source);
                if self.is_bitwise_operator(text) || self.is_arithmetic_operator(text) {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    /// Check a function definition for mixed bitwise/arithmetic operations
    fn check_function(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Track which variables have been used with which operation types
        let mut variable_operations: HashMap<String, HashSet<OperationType>> = HashMap::new();

        // Track line numbers for first occurrence
        let mut variable_locations: HashMap<String, (usize, usize)> = HashMap::new();

        // Collect signed integer parameters
        let signed_int_params = self.collect_signed_int_params(node, source);

        // Track shift operations on signed integer parameters
        let mut shift_operations: HashMap<String, (usize, usize)> = HashMap::new();

        // Recursively analyze all operations in the function
        self.analyze_operations(
            node,
            source,
            &mut variable_operations,
            &mut variable_locations,
            &signed_int_params,
            &mut shift_operations,
        );

        // Check for variables that have both bitwise and arithmetic operations.
        // Skip exactly-2-char variable names like `bi` — these are loop counter/index
        // variables where mixed bitwise+arithmetic is standard embedded pattern
        // (e.g., bit position calculated as `pos + bi`, then used in `1u << bi`).
        // Single-char names like `x` are NOT skipped — they could be function parameters.
        for (var_name, operations) in variable_operations.iter() {
            if var_name.len() == 2 {
                continue;
            }
            if operations.contains(&OperationType::Bitwise)
                && operations.contains(&OperationType::Arithmetic)
            {
                let (line, column) = variable_locations.get(var_name).unwrap_or(&(0, 0));
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Variable '{}' used with both bitwise and arithmetic operations (reduces code readability)",
                        var_name
                    ),
                    file_path: String::new(),
                    line: *line,
                    column: *column,
                    suggestion: Some(
                        "Use separate variables for bitwise and arithmetic operations, or refactor to use only arithmetic operators".to_string()
                    ),
                    ..Default::default()
                });
            }
        }

        // Flag shift operations on signed integer parameters (often used for arithmetic optimization)
        for (var_name, (line, column)) in shift_operations.iter() {
            // Skip if already flagged for mixed operations
            if let Some(ops) = variable_operations.get(var_name) {
                if ops.contains(&OperationType::Bitwise) && ops.contains(&OperationType::Arithmetic)
                {
                    continue;
                }
            }
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message: format!(
                    "Shift operation on signed integer '{}' may be used for arithmetic optimization (use explicit arithmetic instead)",
                    var_name
                ),
                file_path: String::new(),
                line: *line,
                column: *column,
                suggestion: Some(
                    "Use explicit arithmetic operations like * or / instead of shift operations on signed integers".to_string()
                ),
                ..Default::default()
            });
        }
    }

    /// Recursively analyze operations on variables
    fn analyze_operations(
        &self,
        node: &Node,
        source: &str,
        variable_operations: &mut HashMap<String, HashSet<OperationType>>,
        variable_locations: &mut HashMap<String, (usize, usize)>,
        signed_int_params: &HashSet<String>,
        shift_operations: &mut HashMap<String, (usize, usize)>,
    ) {
        // Full-subtree, pre-order scan — order matters because both
        // `variable_locations` and `shift_operations` only record the
        // *first* occurrence for a given variable.
        for node in query::find_descendants_of_kinds(
            *node,
            &[
                "binary_expression",
                "assignment_expression",
                "unary_expression",
            ],
        ) {
            let node = &node;
            match node.kind() {
                "binary_expression" => self.analyze_binary_operation(
                    node,
                    source,
                    variable_operations,
                    variable_locations,
                    signed_int_params,
                    shift_operations,
                ),
                "assignment_expression" => self.analyze_compound_assignment_operation(
                    node,
                    source,
                    variable_operations,
                    variable_locations,
                    signed_int_params,
                    shift_operations,
                ),
                _ => Self::analyze_unary_operation(
                    node,
                    source,
                    variable_operations,
                    variable_locations,
                ),
            }
        }
    }

    /// `binary_expression` case of [`analyze_operations`]: record the
    /// bitwise/arithmetic operation type for each operand variable, and
    /// track shift operations applied to signed integer parameters.
    fn analyze_binary_operation(
        &self,
        node: &Node,
        source: &str,
        variable_operations: &mut HashMap<String, HashSet<OperationType>>,
        variable_locations: &mut HashMap<String, (usize, usize)>,
        signed_int_params: &HashSet<String>,
        shift_operations: &mut HashMap<String, (usize, usize)>,
    ) {
        let Some(op) = self.get_operator(node, source) else {
            return;
        };
        let op_type = if self.is_bitwise_operator(&op) {
            OperationType::Bitwise
        } else if self.is_arithmetic_operator(&op) {
            OperationType::Arithmetic
        } else {
            return;
        };

        // Extract variables from this expression
        let mut vars = HashSet::new();
        Self::extract_variables(node, source, &mut vars);

        // Record operation type for each variable
        for var in vars.iter() {
            variable_operations
                .entry(var.clone())
                .or_default()
                .insert(op_type.clone());

            // Record first location if not already recorded
            if !variable_locations.contains_key(var) {
                let line = node.start_position().row + 1;
                let column = node.start_position().column + 1;
                variable_locations.insert(var.clone(), (line, column));
            }
        }

        // Track shift operations on signed integer parameters
        if self.is_shift_operator(&op) {
            for var in vars.iter() {
                if signed_int_params.contains(var) && !shift_operations.contains_key(var) {
                    let line = node.start_position().row + 1;
                    let column = node.start_position().column + 1;
                    shift_operations.insert(var.clone(), (line, column));
                }
            }
        }
    }

    /// `assignment_expression` case of [`analyze_operations`]: compound
    /// assignment operators (e.g. `x += 1`, `x <<= 2`) record an operation
    /// on the LHS variable, plus shift tracking for signed int parameters.
    fn analyze_compound_assignment_operation(
        &self,
        node: &Node,
        source: &str,
        variable_operations: &mut HashMap<String, HashSet<OperationType>>,
        variable_locations: &mut HashMap<String, (usize, usize)>,
        signed_int_params: &HashSet<String>,
        shift_operations: &mut HashMap<String, (usize, usize)>,
    ) {
        let Some(op_node) = node.child(1) else { return };
        let op_text = get_node_text(&op_node, source);

        let op_type = if matches!(op_text, "+=" | "-=" | "*=" | "/=" | "%=") {
            OperationType::Arithmetic
        } else if matches!(op_text, "<<=" | ">>=" | "&=" | "|=" | "^=") {
            OperationType::Bitwise
        } else {
            return;
        };

        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        if left.kind() != "identifier" {
            return;
        }
        let var = get_node_text(&left, source).to_string();
        variable_operations
            .entry(var.clone())
            .or_default()
            .insert(op_type);

        // Record first location if not already recorded
        if !variable_locations.contains_key(&var) {
            let line = node.start_position().row + 1;
            let column = node.start_position().column + 1;
            variable_locations.insert(var.clone(), (line, column));
        }

        // Track shift compound assignments on signed int params
        if self.is_shift_operator(op_text)
            && signed_int_params.contains(&var)
            && !shift_operations.contains_key(&var)
        {
            let line = node.start_position().row + 1;
            let column = node.start_position().column + 1;
            shift_operations.insert(var, (line, column));
        }
    }

    /// `unary_expression` case of [`analyze_operations`]: `~x` records a
    /// bitwise operation on each variable in the operand.
    fn analyze_unary_operation(
        node: &Node,
        source: &str,
        variable_operations: &mut HashMap<String, HashSet<OperationType>>,
        variable_locations: &mut HashMap<String, (usize, usize)>,
    ) {
        let Some(op_node) = node.child(0) else { return };
        if op_node.kind() != "~" {
            return;
        }
        let Some(operand) = node.child(1) else { return };
        let mut vars = HashSet::new();
        Self::extract_variables(&operand, source, &mut vars);

        for var in vars {
            variable_operations
                .entry(var.clone())
                .or_default()
                .insert(OperationType::Bitwise);

            // Record first location if not already recorded
            variable_locations.entry(var).or_insert_with(|| {
                let line = node.start_position().row + 1;
                let column = node.start_position().column + 1;
                (line, column)
            });
        }
    }
}

impl CertRule for Int14C {
    fn rule_id(&self) -> &'static str {
        "INT14-C"
    }

    fn description(&self) -> &'static str {
        "Avoid performing bitwise and arithmetic operations on the same data"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "INT14-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check function definitions
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function(&func, source, &mut violations);
        }

        violations
    }
}
