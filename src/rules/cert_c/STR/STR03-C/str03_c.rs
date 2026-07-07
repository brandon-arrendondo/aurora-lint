use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Str03C;

impl CertRule for Str03C {
    fn rule_id(&self) -> &'static str {
        "STR03-C"
    }

    fn description(&self) -> &'static str {
        "Do not inadvertently truncate a string"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "STR03-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Str03C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            // Check for function calls that can truncate strings
            if n.kind() == "call_expression" {
                if let Some(function) = n.child_by_field_name("function") {
                    let func_name = ast_utils::get_node_text(&function, source);

                    match func_name {
                        "strncpy" | "strncat" | "snprintf"
                            // Check if there's proper length validation before this call
                            if !self.has_length_validation_before(&n, source) => {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: self.severity(),
                                    message: format!(
                                        "Call to {} may inadvertently truncate string without proper length validation",
                                        func_name
                                    ),
                                    file_path: String::new(),
                                    line: n.start_position().row + 1,
                                    column: n.start_position().column + 1,
                                    suggestion: Some(
                                        "Validate string length before calling truncating functions, or use strcpy() after validation"
                                            .to_string(),
                                    ),
                                    requires_manual_review: Some(true),
                                });
                            }
                        _ => {}
                    }
                }
            }

            // CWE-464: Detect (char)atoi(...) — atoi returns 0 on failure, which becomes
            // a null sentinel '\0' when cast to char, inadvertently truncating strings.
            if n.kind() == "cast_expression" {
                self.check_atoi_char_cast(&n, source, violations);
            }
        }
    }

    /// CWE-464: Detect (char)atoi(...) pattern.
    /// atoi() returns 0 on failure, which when cast to char becomes '\0' (null sentinel).
    fn check_atoi_char_cast(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check if the cast type is char
        if let Some(type_node) = node.child_by_field_name("type") {
            let type_text = ast_utils::get_node_text(&type_node, source);
            if type_text != "char" {
                return;
            }
        } else {
            return;
        }

        // Check if the value is an atoi/strtol call
        if let Some(value) = node.child_by_field_name("value") {
            let call_node = if value.kind() == "call_expression" {
                Some(value)
            } else if value.kind() == "parenthesized_expression" {
                // Handle (char)(atoi(...))
                value.child(1).filter(|c| c.kind() == "call_expression")
            } else {
                None
            };

            if let Some(call) = call_node {
                if let Some(func) = call.child_by_field_name("function") {
                    let func_name = ast_utils::get_node_text(&func, source);
                    if matches!(func_name, "atoi" | "strtol" | "strtoul" | "atol") {
                        let start_point = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "Cast of {}() to char: returns 0 on failure, producing null sentinel '\\0' that truncates strings",
                                func_name
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Use strtol() with error checking, or validate the result is non-zero before casting to char"
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Check if there's length validation before this call
    fn has_length_validation_before(&self, call_node: &Node, source: &str) -> bool {
        // Find the enclosing statement
        let mut current = call_node.parent();
        while let Some(node) = current {
            if matches!(
                node.kind(),
                "compound_statement" | "function_definition" | "translation_unit"
            ) {
                // Look for if statements that validate length
                return self.find_length_check_in_scope(
                    &node,
                    call_node.start_position().row,
                    source,
                );
            }
            current = node.parent();
        }
        false
    }

    /// Search for length validation in the scope before the call
    fn find_length_check_in_scope(
        &self,
        scope_node: &Node,
        call_line: usize,
        source: &str,
    ) -> bool {
        // Any if-statement descendant starting before the call line is a
        // candidate — a descendant starting at/after call_line can never
        // contain a nested if starting earlier (children start no earlier
        // than their parent), so this flat filter is equivalent to the
        // depth-first walk that stopped descending past call_line.
        query::find_descendants_of_kind(*scope_node, "if_statement")
            .into_iter()
            .filter(|n| n.start_position().row < call_line)
            .any(|if_node| {
                let Some(condition) = if_node.child_by_field_name("condition") else {
                    return false;
                };
                let cond_text = ast_utils::get_node_text(&condition, source);
                if !self.is_length_validation(&cond_text) {
                    return false;
                }
                // Accept if the call is in the else branch (safe path)
                if let Some(alternative) = if_node.child_by_field_name("alternative") {
                    if self.is_ancestor(&alternative, call_line) {
                        return true;
                    }
                }
                // Accept if the length check precedes the call in the
                // same scope — the if handles the overlong case (e.g.,
                // error/return), so code after the if is safe.
                if_node.end_position().row < call_line
            })
    }

    /// Check if a condition validates string length
    fn is_length_validation(&self, condition: &str) -> bool {
        // Look for patterns like:
        // - strlen(x) >= sizeof(y)
        // - strlen(x) < sizeof(y)
        // - strlen(x) > n
        (condition.contains("strlen")
            && (condition.contains("sizeof") || condition.contains(">") || condition.contains("<")))
            || (condition.contains("sizeof") && condition.contains("strlen"))
    }

    /// Check if the given line falls within this node's span. A descendant's
    /// span is always a subset of its ancestor's, so checking `node` alone
    /// is equivalent to checking `node` or any of its descendants.
    fn is_ancestor(&self, node: &Node, target_line: usize) -> bool {
        node.start_position().row <= target_line && target_line <= node.end_position().row
    }
}
