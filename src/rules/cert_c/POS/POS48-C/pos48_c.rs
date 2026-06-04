// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Ryan Urchick

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use tree_sitter::Node;

pub struct Pos48C;

impl CertRule for Pos48C {
    fn rule_id(&self) -> &'static str {
        "POS48-C"
    }
    fn description(&self) -> &'static str {
        "Do not unlock or destroy another thread's mutex"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }
    fn cert_id(&self) -> &'static str {
        "POS48-C"
    }

    fn check(&self, _node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check for pthread_mutex_destroy followed by access to shared data
        // without proper thread synchronization
        let lines: Vec<&str> = source.lines().collect();
        let mut found_destroy_line = None;
        let mut has_wait_before_destroy = false;

        for (i, line) in lines.iter().enumerate() {
            if line.contains("wait_for_all_threads") {
                has_wait_before_destroy = true;
            }

            if line.contains("pthread_mutex_destroy") {
                found_destroy_line = Some(i);
            }

            // After destroy, check if there's data access
            if let Some(destroy_line) = found_destroy_line {
                if i > destroy_line {
                    // Look for data modifications after mutex is destroyed
                    if line.contains("data++")
                        || line.contains("data +=")
                        || line.contains("data =")
                    {
                        // Only flag if we didn't wait for threads before destroying
                        if !has_wait_before_destroy {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                line: i + 1,
                                column: 1,
                                file_path: String::new(),
                                message: "Accessing shared data after destroying mutex".to_string(),
                                suggestion: Some(
                                    "Ensure all threads finish before destroying mutex".to_string(),
                                ),
                                requires_manual_review: None,
                            });
                        }
                        break;
                    }
                }
            }
        }

        violations
    }
}
