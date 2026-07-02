// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! ENV02-C: Beware of multiple environment variables with the same effective name
//!
//! This rule detects violations where multiple environment variables are set
//! with names that differ only in case, which can cause issues on case-insensitive systems.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/ENV02-C.+Beware+of+multiple+environment+variables+with+the+same+effective+name

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashMap;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Env02C {
    // Track environment variable names (lowercase) -> original name
    env_vars: RefCell<HashMap<String, String>>,
}

impl Env02C {
    pub fn new() -> Self {
        Env02C {
            env_vars: RefCell::new(HashMap::new()),
        }
    }

    /// Extract environment variable name from putenv/setenv call
    fn get_env_name(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "string_literal" {
            let content = get_node_text(node, source);
            // Remove quotes
            let content = content.trim_matches('"');
            // Extract name before '='
            if let Some(eq_pos) = content.find('=') {
                return Some(content[..eq_pos].to_string());
            }
        }
        None
    }

    /// Check putenv/setenv calls for case-insensitive duplicates
    fn check_env_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if func_name == "putenv" || func_name == "setenv" {
                    if let Some(arguments) = node.child_by_field_name("arguments") {
                        let env_name_opt = if func_name == "setenv" {
                            // setenv("NAME", "value", overwrite) - first argument is the name
                            let mut cursor = arguments.walk();
                            let mut result = None;
                            for child in arguments.children(&mut cursor) {
                                if child.kind() == "string_literal" {
                                    let content = get_node_text(&child, source);
                                    let content = content.trim_matches('"');
                                    result = Some(content.to_string());
                                    break;
                                }
                            }
                            result
                        } else {
                            // putenv("NAME=value") - extract name before '='
                            let mut cursor = arguments.walk();
                            let mut result = None;
                            for child in arguments.children(&mut cursor) {
                                if let Some(name) = self.get_env_name(&child, source) {
                                    result = Some(name);
                                    break;
                                }
                            }
                            result
                        };

                        if let Some(env_name) = env_name_opt {
                            let lowercase_name = env_name.to_lowercase();
                            let mut env_vars = self.env_vars.borrow_mut();

                            if let Some(prev_name) = env_vars.get(&lowercase_name) {
                                if prev_name != &env_name {
                                    violations.push(RuleViolation {
                                        rule_id: "ENV02-C".to_string(),
                                        severity: Severity::Medium,
                                        line: node.start_position().row + 1,
                                        column: node.start_position().column + 1,
                                        message: format!(
                                            "Environment variable '{}' differs only in case from '{}'",
                                            env_name, prev_name
                                        ),
                                        file_path: String::new(),
                                        suggestion: Some("Use consistent casing for environment variable names".to_string()),
                                        requires_manual_review: Some(false),
                                    });
                                }
                            } else {
                                env_vars.insert(lowercase_name, env_name);
                            }
                        }
                    }
                }
            }
        }
    }

    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            self.check_env_call(&n, source, violations);
        }
    }
}

impl Default for Env02C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Env02C {
    fn rule_id(&self) -> &'static str {
        "ENV02-C"
    }

    fn description(&self) -> &'static str {
        "Beware of multiple environment variables with the same effective name"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ENV02-C"
    }

    fn check(&self, root_node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.env_vars.borrow_mut().clear();
        self.check_node(root_node, source, &mut violations);
        violations
    }
}
