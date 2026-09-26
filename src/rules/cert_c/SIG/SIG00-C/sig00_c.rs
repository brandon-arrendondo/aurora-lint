// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! SIG00-C: Mask signals handled by noninterruptible signal handlers
//!
//! This rule ensures that signal handlers that require noninterruptible execution
//! are properly protected from race conditions by using signal masking.
//!
//! ## Non-compliant example:
//!
//! ```c
//! // Using signal() - does not provide signal masking
//! signal(SIGUSR1, handler);
//!
//! // Using sigaction() without masking
//! struct sigaction act;
//! act.sa_handler = handler;
//! sigaction(SIGUSR1, &act, NULL);  // No signal masking configured
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! struct sigaction act;
//! act.sa_handler = handler;
//! sigemptyset(&act.sa_mask);
//! sigaddset(&act.sa_mask, SIGUSR1);  // Mask signal during handler execution
//! sigaddset(&act.sa_mask, SIGUSR2);
//! sigaction(SIGUSR1, &act, NULL);
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::signal_handlers::{RegisteredHandlers, RegistrationKind};
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Sig00C;

impl Sig00C {
    pub fn new() -> Self {
        Self
    }

    /// Check for calls to signal() function
    fn check_signal_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() != "call_expression" {
            return;
        }

        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            if function_name == "signal" {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: "Use of signal() function detected. signal() does not provide signal masking and can lead to race conditions in noninterruptible signal handlers. Use sigaction() with proper signal masking instead.".to_string(),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(
                        "Replace signal() with sigaction() and configure sa_mask to mask signals during handler execution using sigemptyset() and sigaddset()."
                            .to_string(),
                    ),
                    ..Default::default()
                });
            }
        }
    }

    /// A sigaction() that installs a handler with nothing added to sa_mask.
    fn report_unmasked_sigaction(&self, node: &Node, violations: &mut Vec<RuleViolation>) {
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::Medium,
            message: "sigaction() call detected without apparent signal masking. Ensure sa_mask is properly configured with sigaddset() before calling sigaction().".to_string(),
            file_path: String::new(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            suggestion: Some(
                "Use sigemptyset() and sigaddset() to configure sa_mask before calling sigaction() to prevent race conditions in signal handlers."
                    .to_string(),
            ),
            ..Default::default()
        });
    }
}

impl CertRule for Sig00C {
    fn rule_id(&self) -> &'static str {
        "SIG00-C"
    }

    fn description(&self) -> &'static str {
        "Mask signals handled by noninterruptible signal handlers"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "SIG00-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Sig00C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Only a call that installs a handler is in scope: signal(SIGPIPE,
        // SIG_IGN) masks nothing because nothing runs. The resolver ties each
        // registration to the signal()/sigaction() call that performs it, and
        // knows the mask of the struct sigaction that call is given.
        let registrations = RegisteredHandlers::collect(node, source).registrations;
        let mut signal_sites = HashSet::new();
        let mut sigaction_masked: HashMap<(usize, usize), bool> = HashMap::new();
        for r in &registrations {
            let site = (r.api_line, r.api_column);
            match r.kind {
                RegistrationKind::Signal => {
                    signal_sites.insert(site);
                }
                RegistrationKind::Sigaction { .. } => {
                    let masked = sigaction_masked.entry(site).or_insert(true);
                    *masked &= !r.mask.is_empty();
                }
                _ => {}
            }
        }
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            let site = (
                call.start_position().row + 1,
                call.start_position().column + 1,
            );
            if signal_sites.contains(&site) {
                self.check_signal_call(&call, source, violations);
            } else if sigaction_masked.get(&site) == Some(&false) {
                self.report_unmasked_sigaction(&call, violations);
            }
        }
    }
}
