//! ERR30-C: Take care when reading errno
//!
//! This rule ensures that errno is used correctly when calling C standard library functions:
//!
//! 1. **Out-of-band error indicators** (ftell, signal, mbrtowc, etc.)
//!    - Must check the function's return value BEFORE examining errno
//!    - errno should only be checked AFTER confirming an error occurred via return value
//!
//! 2. **In-band error indicators** (strtoul, strtod, fgetwc, etc.)
//!    - Must set errno = 0 BEFORE calling the function
//!    - Return value alone is ambiguous, so errno must be pre-zeroed to detect errors
//!
//! 3. **Functions without errno guarantees** (setlocale, printf, etc.)
//!    - Should not rely solely on errno for error detection
//!
//! ## Detected Violations:
//! - Checking errno without prior return value verification (out-of-band functions)
//! - Calling in-band functions without first setting errno = 0
//! - Reading errno after functions that don't guarantee to set it
//!
//! ## Compliant Patterns:
//! - Out-of-band: `if (ftell(fp) == -1) { /* check errno */ }`
//! - In-band: `errno = 0; val = strtoul(str, &end, 10); if (errno == ERANGE) { ... }`

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Err30C;

impl CertRule for Err30C {
    fn rule_id(&self) -> &'static str {
        "ERR30-C"
    }

    fn description(&self) -> &'static str {
        "Take care when reading errno"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ERR30-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Err30C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kinds(*node, &["if_statement", "call_expression"]) {
            match n.kind() {
                // Check for errno usage in if conditions
                "if_statement" => {
                    self.check_errno_in_if(&n, source, violations);
                }
                // Check for in-band function calls without errno initialization
                "call_expression" => {
                    self.check_inband_function_call(&n, source, violations);
                }
                _ => {}
            }
        }
    }

    /// Check if errno is examined in an if condition without prior error return value check
    fn check_errno_in_if(&self, if_node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(condition) = if_node.child_by_field_name("condition") {
            let condition_text = get_node_text(&condition, source);

            // Check if condition examines errno
            if condition_text.contains("errno") {
                // Look backwards to find the most recent out-of-band function call
                if let Some(recent_call) = self.find_recent_outofband_call(if_node, source) {
                    let function_name =
                        if let Some(func_node) = recent_call.child_by_field_name("function") {
                            get_node_text(&func_node, source)
                        } else {
                            "<unknown>"
                        };

                    // Check if the return value was properly checked before the errno check
                    if !self.has_return_value_check_before_errno(&recent_call, if_node, source) {
                        let start_point = condition.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "errno checked without verifying error occurred via return value of '{}' - must check return value first",
                                function_name
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(format!(
                                "Check return value before errno: 'if ({}(...) == ERROR_VALUE) {{ if (errno) {{ ... }} }}'",
                                function_name
                            )),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Check if an in-band function is called without errno being reset first
    fn check_inband_function_call(
        &self,
        call_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(function_node) = call_node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            if self.is_inband_function(&function_name) {
                // Check if errno = 0 appears before this call
                if !self.has_errno_reset_before(call_node, source) {
                    let start_point = call_node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "In-band function '{}' called without setting errno = 0 first - errno must be reset before calling in-band functions",
                            function_name
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(format!(
                            "Set errno before call: 'errno = 0; val = {}(...); if (errno == ERANGE) {{ ... }}'",
                            function_name
                        )),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check if there's an errno reset (errno = 0) before the given node
    fn has_errno_reset_before(&self, call_node: &Node, source: &str) -> bool {
        // Walk up to find the containing compound statement
        let mut current = call_node.parent();
        while let Some(parent) = current {
            if parent.kind() == "compound_statement" || parent.kind() == "function_definition" {
                // Search for errno = 0 in preceding statements
                let call_byte_start = call_node.start_byte();

                for i in 0..parent.child_count() {
                    if let Some(child) = parent.child(i) {
                        // Only look at statements before the call
                        if child.end_byte() < call_byte_start {
                            if self.contains_errno_reset(&child, source) {
                                return true;
                            }
                        }
                    }
                }
                break;
            }
            current = parent.parent();
        }
        false
    }

    /// Check if a node contains errno = 0 assignment
    fn contains_errno_reset(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "assignment_expression" {
                return false;
            }
            let (Some(left), Some(right)) = (
                n.child_by_field_name("left"),
                n.child_by_field_name("right"),
            ) else {
                return false;
            };
            let left_text = get_node_text(&left, source);
            let right_text = get_node_text(&right, source);
            left_text == "errno" && right_text == "0"
        })
        .is_some()
    }

    /// Find the most recent out-of-band function call before the given node
    fn find_recent_outofband_call<'a>(&self, if_node: &Node<'a>, source: &str) -> Option<Node<'a>> {
        // Walk up to find the containing compound statement
        let mut current = if_node.parent();
        while let Some(parent) = current {
            if parent.kind() == "compound_statement" || parent.kind() == "function_definition" {
                // Search for out-of-band calls in preceding statements
                let if_byte_start = if_node.start_byte();
                let mut most_recent: Option<Node> = None;

                for i in 0..parent.child_count() {
                    if let Some(child) = parent.child(i) {
                        // Only look at statements before the if
                        if child.end_byte() < if_byte_start {
                            if let Some(call) = self.find_outofband_call_in_node(&child, source) {
                                // Keep track of the most recent (closest to if_node)
                                most_recent = Some(call);
                            }
                        }
                    }
                }
                return most_recent;
            }
            current = parent.parent();
        }
        None
    }

    /// Find an out-of-band function call in a node
    fn find_outofband_call_in_node<'a>(&self, node: &Node<'a>, source: &str) -> Option<Node<'a>> {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(function_node) = n.child_by_field_name("function") else {
                return false;
            };
            let function_name = get_node_text(&function_node, source);
            self.is_outofband_function(&function_name)
        })
    }

    /// Check if the return value of a function was checked before errno was examined
    fn has_return_value_check_before_errno(
        &self,
        call_node: &Node,
        errno_if_node: &Node,
        source: &str,
    ) -> bool {
        // Look for an if statement between the call and the errno check that validates return value
        let call_end = call_node.end_byte();
        let errno_start = errno_if_node.start_byte();

        if let Some(function_node) = call_node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            // Walk up from call to find compound statement
            let mut current = call_node.parent();
            while let Some(parent) = current {
                if parent.kind() == "compound_statement" || parent.kind() == "function_definition" {
                    // Search for if statements that check the return value
                    for i in 0..parent.child_count() {
                        if let Some(child) = parent.child(i) {
                            // Look for if statements between the call and errno check
                            if child.start_byte() >= call_end && child.end_byte() <= errno_start {
                                if child.kind() == "if_statement" {
                                    if let Some(condition) = child.child_by_field_name("condition")
                                    {
                                        let condition_text = get_node_text(&condition, source);

                                        // Check if condition validates return value
                                        if self.checks_return_value_for_function(
                                            &condition_text,
                                            &function_name,
                                        ) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    break;
                }
                current = parent.parent();
            }
        }

        false
    }

    /// Check if a condition text checks the return value appropriately for a function
    fn checks_return_value_for_function(&self, condition: &str, function_name: &str) -> bool {
        match function_name {
            "ftell" => condition.contains("== -1") || condition.contains("== -1L"),
            "fopen" | "freopen" => {
                condition.contains("== NULL")
                    || condition.contains("!= NULL")
                    || condition.contains("== 0")
                    || condition.contains("!= 0")
            }
            "signal" => condition.contains("== SIG_ERR"),
            "mbrtowc" | "wcrtomb" => {
                condition.contains("== (size_t)-1") || condition.contains("< 0")
            }
            _ => {
                // Generic check: looking for comparison operators
                condition.contains("==")
                    || condition.contains("!=")
                    || condition.contains("<")
                    || condition.contains(">")
            }
        }
    }

    /// Returns true if the function is an out-of-band error indicator
    /// (return value can indicate error without errno ambiguity)
    fn is_outofband_function(&self, function_name: &str) -> bool {
        matches!(
            function_name,
            "ftell"
                | "fopen"
                | "freopen"
                | "fclose"
                | "fflush"
                | "fseek"
                | "signal"
                | "mbrtowc"
                | "wcrtomb"
                | "mbtowc"
                | "wctomb"
        )
    }

    /// Returns true if the function is an in-band error indicator
    /// (return value is ambiguous, must use errno)
    fn is_inband_function(&self, function_name: &str) -> bool {
        matches!(
            function_name,
            "strtol"
                | "strtoul"
                | "strtoll"
                | "strtoull"
                | "strtof"
                | "strtod"
                | "strtold"
                | "fgetwc"
                | "fgetws"
                | "getwc"
                | "getwchar"
        )
    }
}
