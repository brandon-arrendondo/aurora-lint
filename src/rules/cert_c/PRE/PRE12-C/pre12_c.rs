// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Ryan Urchick

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pre12C;

impl CertRule for Pre12C {
    fn rule_id(&self) -> &'static str {
        "PRE12-C"
    }
    fn description(&self) -> &'static str {
        "Do not define unsafe macros"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }
    fn cert_id(&self) -> &'static str {
        "PRE12-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Pre12C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            // Look for preprocessor macro definitions
            if n.kind() == "preproc_function_def" {
                let text = n.utf8_text(source.as_bytes()).unwrap_or("");

                // Skip macros using __extension__ (GCC extension that handles evaluation correctly)
                if !text.contains("__extension__") {
                    // Check if macro uses parameters multiple times in definition
                    // Extract parameter names from #define NAME(param1, param2)
                    if let Some(params) = self.extract_macro_params(text) {
                        let definition = text.split(')').skip(1).collect::<String>();

                        // Check if any parameter appears more than once in the definition
                        for param in params {
                            // Count occurrences of parameter as standalone identifier
                            let mut count = 0;
                            for word in definition.split(|c: char| !c.is_alphanumeric() && c != '_')
                            {
                                if word == param {
                                    count += 1;
                                }
                            }

                            if count > 1 {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: self.severity(),
                                    line: n.start_position().row + 1,
                                    column: n.start_position().column + 1,
                                    file_path: String::new(),
                                    message: format!("Macro evaluates parameter '{}' multiple times; use inline function instead", param),
                                    suggestion: Some("Replace macro with inline function to avoid multiple evaluation".to_string()),
                                    requires_manual_review: None,
                                });
                                break; // Only report once per macro
                            }
                        }
                    }
                }
            }

            // Also detect expanded macro patterns: expressions with multiple side-effects
            // Pattern: (expr) ? -(expr) : (expr) where expr has side effects like ++n
            if n.kind() == "assignment_expression" || n.kind() == "conditional_expression" {
                let text = n.utf8_text(source.as_bytes()).unwrap_or("");

                // Check for increment/decrement operators appearing multiple times
                if text.contains("++") || text.contains("--") {
                    // Count occurrences of side-effect operators
                    let inc_count = text.matches("++").count() + text.matches("--").count();

                    // If there are 3+ occurrences, it's likely from macro expansion
                    if inc_count >= 3 && (text.contains('?') || text.contains(':')) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            line: n.start_position().row + 1,
                            column: n.start_position().column + 1,
                            file_path: String::new(),
                            message: "Expression with multiple side-effects; likely from unsafe macro expansion".to_string(),
                            suggestion: Some("Avoid passing expressions with side effects to macros".to_string()),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }
    }

    fn extract_macro_params(&self, text: &str) -> Option<Vec<String>> {
        // Extract params from #define NAME(param1, param2) definition
        if let Some(start) = text.find('(') {
            if let Some(end) = text.find(')') {
                let params_str = &text[start + 1..end];
                let params: Vec<String> = params_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !params.is_empty() {
                    return Some(params);
                }
            }
        }
        None
    }
}
