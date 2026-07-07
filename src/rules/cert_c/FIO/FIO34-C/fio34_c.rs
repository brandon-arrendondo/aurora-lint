//! FIO34-C: Distinguish between characters read from a file and EOF or WEOF
//!
//! This rule ensures that character input functions (getc, fgetc, getchar)
//! have their return values stored in int variables to properly distinguish
//! between valid characters and EOF/WEOF values.
//!
//! KEY DISTINCTIONS:
//! - Character INPUT functions (getc, fgetc, getchar): Must store in int before comparison
//! - Character MANIPULATION functions (ungetc): Can be directly compared with EOF
//!
//! VIOLATIONS:
//! - char c = getc(file);           // char cannot hold EOF
//! - while ((char c = getc()) != EOF)  // char comparison with EOF
//!
//! VALID PATTERNS:
//! - int c = getc(file);            // int can distinguish EOF
//! - if (ungetc(c, file) == EOF)    // ungetc designed for EOF comparison
//! - while ((c = getc()) != EOF) where c is int

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Fio34C;

impl Fio34C {
    pub fn new() -> Self {
        Self
    }
}

impl CertRule for Fio34C {
    fn rule_id(&self) -> &'static str {
        "FIO34-C"
    }

    fn description(&self) -> &'static str {
        "Distinguish between characters read from a file and EOF or WEOF"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "FIO34-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Fio34C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let matched = query::find_descendants_of_kinds(
            *node,
            &[
                "function_definition",
                "assignment_expression",
                "init_declarator",
                "binary_expression",
                "while_statement",
                "do_statement",
                "for_statement",
                "cast_expression",
            ],
        );
        for n in matched {
            match n.kind() {
                "function_definition" => {
                    // Check for EOF comparison without feof/ferror verification
                    self.check_eof_without_verification(&n, source, violations);
                }
                "assignment_expression" => {
                    self.check_assignment(&n, source, violations);
                }
                "init_declarator" => {
                    self.check_init_declarator(&n, source, violations);
                }
                "binary_expression" => {
                    self.check_comparison(&n, source, violations);
                }
                "while_statement" | "do_statement" | "for_statement" => {
                    self.check_loop_condition(&n, source, violations);
                }
                "cast_expression" => {
                    self.check_cast_expression(&n, source, violations);
                }
                _ => {}
            }
        }
    }

    /// Check for char variables being assigned from getc/fgetc/getchar
    fn check_assignment(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            if right.kind() == "call_expression" {
                if let Some(function) = right.child_by_field_name("function") {
                    let function_name = get_node_text(&function, source);

                    if self.is_character_input_function(function_name) {
                        // Check if the left side is a char type variable
                        if self.is_char_type_variable(&left, source) {
                            self.report_char_assignment_violation(
                                node,
                                function_name,
                                source,
                                violations,
                            );
                        }
                        // Check if it's a wide char function assigned to wchar_t (should be wint_t)
                        if self.is_wide_character_function(function_name)
                            && self.is_wchar_type_variable(&left, source)
                        {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                message: format!(
                                    "Variable assigned from {}() should be wint_t, not wchar_t",
                                    function_name
                                ),
                                file_path: String::new(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                suggestion: Some(
                                    "Use wint_t to properly distinguish WEOF from valid wide characters".to_string()
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    /// Check for char variables being initialized from getc/fgetc/getchar
    fn check_init_declarator(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for pattern: char c = getc(file);
        if let Some(value) = node.child_by_field_name("value") {
            if value.kind() == "call_expression" {
                if let Some(function) = value.child_by_field_name("function") {
                    let function_name = get_node_text(&function, source);

                    if self.is_character_input_function(function_name) {
                        // Check if this is a char declaration
                        if let Some(_declarator) = node.child_by_field_name("declarator") {
                            if self.is_char_declaration(node, source) {
                                self.report_char_init_violation(
                                    node,
                                    function_name,
                                    source,
                                    violations,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check for direct comparison of getc/fgetc result with EOF
    fn check_comparison(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let node_text = get_node_text(node, source);

        // Look for patterns like: getc(file) == EOF or getc(file) != EOF
        if node_text.contains("EOF") || node_text.contains("WEOF") {
            if let Some(operator) = node.child_by_field_name("operator") {
                let op_text = get_node_text(&operator, source);
                if op_text == "==" || op_text == "!=" {
                    // Check if either side is a direct call to character input function
                    if let Some(left) = node.child_by_field_name("left") {
                        if self.contains_unchecked_char_input(&left, source) {
                            self.report_direct_comparison_violation(node, source, violations);
                            return;
                        }
                    }
                    if let Some(right) = node.child_by_field_name("right") {
                        if self.contains_unchecked_char_input(&right, source) {
                            self.report_direct_comparison_violation(node, source, violations);
                        }
                    }
                }
            }
        }
    }

    /// Check loop conditions for problematic patterns
    fn check_loop_condition(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Pattern: while ((c = getc(file)) != EOF) where c is char
        if let Some(condition) = node.child_by_field_name("condition") {
            self.check_loop_condition_pattern(&condition, source, violations);
        }
    }

    fn check_loop_condition_pattern(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let node_text = get_node_text(node, source);

        // Look for assignment within condition
        if node.kind() == "parenthesized_expression" {
            if let Some(inner) = node.child(1) {
                // Skip the opening paren
                self.check_loop_condition_pattern(&inner, source, violations);
            }
        } else if node.kind() == "binary_expression" {
            // Check for pattern: (c = getc(...)) != EOF where c is char
            if node_text.contains("EOF") || node_text.contains("WEOF") {
                if let Some(left) = node.child_by_field_name("left") {
                    // Need to check if the assignment uses a char variable
                    self.check_assignment_expression_for_char(&left, source, violations, node);
                }
            }
        }
    }

    /// Check if an assignment expression in a loop condition uses a char variable
    fn check_assignment_expression_for_char(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        parent: &Node,
    ) {
        if node.kind() == "parenthesized_expression" {
            if let Some(inner) = node.child(1) {
                self.check_assignment_expression_for_char(&inner, source, violations, parent);
            }
        } else if node.kind() == "assignment_expression" {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                if right.kind() == "call_expression" {
                    if let Some(function) = right.child_by_field_name("function") {
                        let function_name = get_node_text(&function, source);
                        if self.is_character_input_function(function_name) {
                            // Check if left is a char variable
                            if self.is_char_type_variable(&left, source) {
                                self.report_loop_condition_violation(parent, source, violations);
                            }
                            // Check if it's a wide char function assigned to wchar_t
                            if self.is_wide_character_function(function_name)
                                && self.is_wchar_type_variable(&left, source)
                            {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: self.severity(),
                                    message: "Loop condition assigns wide character function to wchar_t instead of wint_t".to_string(),
                                    file_path: String::new(),
                                    line: parent.start_position().row + 1,
                                    column: parent.start_position().column + 1,
                                    suggestion: Some(
                                        "Use wint_t to properly distinguish WEOF from valid wide characters".to_string()
                                    ),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Character input functions that read from streams
    /// These should have results stored in int variables before EOF comparison
    fn is_character_input_function(&self, name: &str) -> bool {
        matches!(
            name,
            "getc" | "fgetc" | "getchar" | "getwc" | "fgetwc" | "getwchar"
        )
    }

    /// Character manipulation functions that return status codes
    /// These are designed to be compared directly with EOF
    fn is_character_manipulation_function(&self, name: &str) -> bool {
        matches!(name, "ungetc" | "ungetwc")
    }

    /// All functions that work with character I/O (for general detection)
    #[allow(dead_code)]
    fn is_character_io_function(&self, name: &str) -> bool {
        self.is_character_input_function(name) || self.is_character_manipulation_function(name)
    }

    /// Helper: Check if a function is a wide character input function
    fn is_wide_character_function(&self, name: &str) -> bool {
        matches!(name, "getwc" | "fgetwc" | "getwchar")
    }

    /// Helper: Check if a variable is of char type
    fn is_char_type_variable(&self, node: &Node, source: &str) -> bool {
        // This is a simplified check - in production, would need proper type analysis
        // Check if the variable was declared as char
        let var_name = get_node_text(node, source);

        // Walk up to find the declaration
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "function_definition" || parent.kind() == "compound_statement" {
                // Search for char declarations in this scope
                let scope_text = get_node_text(&parent, source);
                if scope_text.contains(&format!("char {}", var_name))
                    || scope_text.contains(&format!("char *{}", var_name))
                    || scope_text.contains(&format!("unsigned char {}", var_name))
                    || scope_text.contains(&format!("signed char {}", var_name))
                {
                    return true;
                }
                break;
            }
            current = parent.parent();
        }
        false
    }

    /// Helper: Check if a variable is of wchar_t type (should be wint_t for getwc)
    fn is_wchar_type_variable(&self, node: &Node, source: &str) -> bool {
        let var_name = get_node_text(node, source);

        // Walk up to find the declaration
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "function_definition" || parent.kind() == "compound_statement" {
                // Search for wchar_t declarations in this scope
                let scope_text = get_node_text(&parent, source);
                if scope_text.contains(&format!("wchar_t {}", var_name)) {
                    return true;
                }
                break;
            }
            current = parent.parent();
        }
        false
    }

    /// Check for casts to char of character input function results
    fn check_cast_expression(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for (char)getc(...) or (char)fgetc(...) etc.
        if let Some(type_node) = node.child_by_field_name("type") {
            let type_text = get_node_text(&type_node, source);

            // Check if casting to char type
            if type_text.contains("char") && !type_text.contains("*") {
                // Check if the value being cast is from a character input function
                if let Some(value) = node.child_by_field_name("value") {
                    if value.kind() == "call_expression" {
                        if let Some(function) = value.child_by_field_name("function") {
                            let function_name = get_node_text(&function, source);

                            if self.is_character_input_function(function_name) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: self.severity(),
                                    message: format!(
                                        "Casting {}() result to char loses EOF distinction",
                                        function_name
                                    ),
                                    file_path: String::new(),
                                    line: node.start_position().row + 1,
                                    column: node.start_position().column + 1,
                                    suggestion: Some(
                                        "Store result in int variable before comparison with EOF"
                                            .to_string(),
                                    ),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Helper: Check if this is a char declaration
    fn is_char_declaration(&self, node: &Node, source: &str) -> bool {
        // Look for the type specifier in the parent declaration
        if let Some(parent) = node.parent() {
            if parent.kind() == "declaration" {
                // Check for char type specifier
                for i in 0..parent.child_count() {
                    if let Some(child) = parent.child(i) {
                        if child.kind() == "primitive_type" || child.kind() == "type_identifier" {
                            let type_text = get_node_text(&child, source);
                            if type_text == "char" {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Helper: Check if a node contains unchecked character INPUT (not manipulation)
    fn contains_unchecked_char_input(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let function_name = get_node_text(&function, source);
                // Only flag character INPUT functions, not manipulation functions
                if self.is_character_input_function(function_name) {
                    return true;
                }
                // Do NOT flag character manipulation functions like ungetc
                if self.is_character_manipulation_function(function_name) {
                    return false;
                }
            }
        }

        // Check if it's a char variable that was assigned from getc/fgetc (not ungetc)
        if node.kind() == "identifier" {
            if self.is_char_type_variable(node, source) {
                // This char variable might have been assigned from getc
                // Would need data flow analysis to be certain
                return true;
            }
        }

        false
    }

    /// Helper: Check if text contains char variable with getc pattern
    #[allow(dead_code)]
    fn contains_char_getc_pattern(&self, _text: &str) -> bool {
        // This needs to actually check if the variable is char type
        // For now, return false - we need proper type checking in loop conditions
        false
    }

    /// Report violation for char assignment from getc/fgetc
    fn report_char_assignment_violation(
        &self,
        node: &Node,
        function_name: &str,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let start_point = node.start_position();
        let node_text = get_node_text(node, source);

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "Character from '{}' stored in char variable may not distinguish EOF: '{}'",
                function_name, node_text
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(format!(
                "Use 'int' instead of 'char' to store the result of '{}' and properly check for EOF",
                function_name
            )),
        ..Default::default()
        });
    }

    /// Report violation for char initialization from getc/fgetc
    fn report_char_init_violation(
        &self,
        node: &Node,
        function_name: &str,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let start_point = node.start_position();
        let node_text = get_node_text(node, source);

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "Character from '{}' initialized to char variable, cannot distinguish EOF: '{}'",
                function_name, node_text
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(format!(
                "Declare variable as 'int' instead of 'char' to properly handle EOF from '{}'",
                function_name
            )),
            ..Default::default()
        });
    }

    /// Report violation for direct EOF comparison
    fn report_direct_comparison_violation(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let start_point = node.start_position();
        let node_text = get_node_text(node, source);

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "Direct comparison with EOF/WEOF may fail with char type: '{}'",
                node_text
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(
                "Store result in 'int' (or 'wint_t' for wide chars) before comparing with EOF/WEOF"
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    /// Report violation for loop condition pattern
    fn report_loop_condition_violation(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let start_point = node.start_position();
        let node_text = get_node_text(node, source);

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "Loop condition with char type may not properly detect EOF: '{}'",
                node_text
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some("Use 'int' for the loop variable to properly detect EOF".to_string()),
            ..Default::default()
        });
    }

    /// Check for EOF comparison without feof()/ferror() verification
    fn check_eof_without_verification(
        &self,
        func_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for patterns like: while ((c = getchar()) != EOF) without feof/ferror
        let has_eof_comparison = self.has_eof_comparison_in_loop(func_node, source);
        let has_feof_call = self.has_feof_or_ferror_call(func_node, source);

        if has_eof_comparison && !has_feof_call {
            // Find the loop with EOF comparison to report
            self.find_and_report_eof_loops(func_node, source, violations);
        }
    }

    /// Check if function contains a loop comparing to EOF
    fn has_eof_comparison_in_loop(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            matches!(
                n.kind(),
                "while_statement" | "do_statement" | "for_statement"
            ) && self.loop_compares_to_eof(&n, source)
        })
        .is_some()
    }

    /// Check if a loop compares to EOF
    fn loop_compares_to_eof(&self, loop_node: &Node, source: &str) -> bool {
        // Check the loop's condition for EOF comparison
        let condition = match loop_node.kind() {
            "while_statement" => loop_node.child_by_field_name("condition"),
            "do_statement" => loop_node.child_by_field_name("condition"),
            "for_statement" => loop_node.child_by_field_name("condition"),
            _ => None,
        };

        if let Some(cond) = condition {
            return self.contains_eof_comparison(&cond, source);
        }
        false
    }

    /// Check if an expression contains EOF comparison with getchar/getc/fgetc
    fn contains_eof_comparison(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            let node_text = get_node_text(&n, source);

            // Check for patterns like: (c = getchar()) != EOF or c != EOF
            if node_text.contains("EOF") || node_text.contains("WEOF") {
                // Also check for character input function calls
                if node_text.contains("getchar")
                    || node_text.contains("getc")
                    || node_text.contains("fgetc")
                {
                    return true;
                }
                // Check if there's any getchar/getc/fgetc call in the loop body
                if n.kind() == "binary_expression" {
                    return true;
                }
            }
            false
        })
        .is_some()
    }

    /// Check if function contains feof() or ferror() calls
    fn has_feof_or_ferror_call(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() == "call_expression" {
                if let Some(function) = n.child_by_field_name("function") {
                    let func_name = get_node_text(&function, source);
                    if func_name == "feof" || func_name == "ferror" {
                        return true;
                    }
                }
            }
            false
        })
        .is_some()
    }

    /// Find and report loops with EOF comparisons
    fn find_and_report_eof_loops(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for loop_node in query::find_descendants_of_kinds(
            *node,
            &["while_statement", "do_statement", "for_statement"],
        ) {
            if self.loop_compares_to_eof(&loop_node, source) {
                self.report_eof_verification_violation(&loop_node, source, violations);
            }
        }
    }

    /// Report violation for EOF comparison without feof/ferror verification
    fn report_eof_verification_violation(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let start_point = node.start_position();
        let node_text = get_node_text(node, source);
        // Get just the first line for clearer message
        let first_line = node_text.lines().next().unwrap_or(node_text);

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "EOF comparison without feof()/ferror() verification: '{}'",
                first_line.trim()
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some("After EOF is detected, call feof() and ferror() to distinguish between end-of-file and I/O error".to_string()),
        ..Default::default()
        });
    }
}
