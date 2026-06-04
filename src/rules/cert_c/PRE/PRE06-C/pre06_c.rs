// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Ryan Urchick

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use tree_sitter::Node;

pub struct Pre06C;

impl CertRule for Pre06C {
    fn rule_id(&self) -> &'static str {
        "PRE06-C"
    }
    fn description(&self) -> &'static str {
        "Enclose header files in an include guard"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }
    fn cert_id(&self) -> &'static str {
        "PRE06-C"
    }

    fn applies_to_file(&self, file_path: &str) -> bool {
        matches!(
            std::path::Path::new(file_path)
                .extension()
                .and_then(|e| e.to_str()),
            Some("h" | "hpp" | "hh" | "hxx")
        )
    }

    fn check(&self, _node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check if source has #ifndef, #define, #endif pattern
        let has_ifndef = source.contains("#ifndef");
        let has_define = source.contains("#define");
        let has_endif = source.contains("#endif");

        if !has_ifndef || !has_define || !has_endif {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                line: 1,
                column: 1,
                file_path: String::new(),
                message: "Header file missing include guard".to_string(),
                suggestion: Some(
                    "Add #ifndef HEADER_H / #define HEADER_H / #endif guard".to_string(),
                ),
                requires_manual_review: None,
            });
        }

        violations
    }
}
