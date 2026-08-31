// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! MSC14-C: Do not introduce unnecessary platform dependencies
//!
//! This rule targets the concrete, statically checkable platform dependency
//! from the wiki's own example: `strerror_r()` has two incompatible
//! signatures across platforms -- the POSIX/XSI version returns `int` (an
//! error code) and writes the message into the supplied buffer, while the
//! GNU version returns `char *` (a pointer to the message, not always the
//! supplied buffer). Using its return value directly as a string (e.g.
//! inline as a `%s` argument) silently assumes GNU semantics and breaks on
//! XSI-compliant platforms. The portable idiom captures the return value in
//! an `int`, checks it, and then reads the message from the buffer itself.
//!
//! Note: the wiki's other example -- `~si` (bitwise complement) on a signed
//! operand used for overflow detection -- is a platform dependency too, but
//! that exact pattern is already covered by INT13-C ("Use bitwise operators
//! only on unsigned operands"); this rule does not duplicate it. Recorded in
//! this rule's TOML as `[references] related = ["INT13-C"]` (task 626,
//! cross-rule overlap policy: docs/design/cross-rule-overlap.md). This is a
//! `related` tag, not a validated `defers_to` exception -- task 625 found no
//! ground-truth-labeled co-located data for this pair either way, so the
//! subsumption bar is unmet; re-examine if either rule's detection logic
//! changes or labeled data accumulates.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/MSC14-C.+Do+not+introduce+unnecessary+platform+dependencies

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Msc14C;

impl Msc14C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Msc14C
    }

    fn traverse(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*root, "call_expression") {
            let Some(func) = call.child_by_field_name("function") else {
                continue;
            };
            if func.kind() != "identifier"
                || ast_utils::get_node_text(&func, source) != "strerror_r"
            {
                continue;
            }

            // Compliant usage is `result = strerror_r(...)` (or a plain
            // `int result = strerror_r(...)` init-declarator) -- the call is
            // the direct right-hand side of an assignment/initializer. Any
            // other context (used inline as an argument, printed directly,
            // etc.) assumes the GNU char*-returning signature.
            let Some(parent) = call.parent() else {
                continue;
            };
            let directly_assigned = match parent.kind() {
                "init_declarator" => parent.child_by_field_name("value") == Some(call),
                "assignment_expression" => parent.child_by_field_name("right") == Some(call),
                _ => false,
            };
            if directly_assigned {
                continue;
            }

            let pos = call.start_position();
            violations.push(RuleViolation {
                rule_id: "MSC14-C".to_string(),
                severity: Severity::Low,
                line: pos.row + 1,
                column: pos.column + 1,
                message: "strerror_r() return value used directly -- its return type (int vs. char*) differs between POSIX/XSI and GNU implementations".to_string(),
                file_path: String::new(),
                suggestion: Some(
                    "Capture the return value in an int, check it for an error, and read the message from the supplied buffer rather than using the return value directly"
                        .to_string(),
                ),
                requires_manual_review: Some(false),
            });
        }
    }
}

impl CertRule for Msc14C {
    fn rule_id(&self) -> &'static str {
        "MSC14-C"
    }

    fn description(&self) -> &'static str {
        "Do not introduce unnecessary platform dependencies"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "MSC14-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
