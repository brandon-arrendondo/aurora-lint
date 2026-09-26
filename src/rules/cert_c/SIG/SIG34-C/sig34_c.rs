// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{get_identifier_from_declarator, get_node_text};
use crate::utility::cert_c::signal_handlers::RegisteredHandlers;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Sig34C;

impl CertRule for Sig34C {
    fn rule_id(&self) -> &'static str {
        "SIG34-C"
    }

    fn description(&self) -> &'static str {
        "Do not call signal() from within interruptible signal handlers"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        self.rule_id()
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.find_signal_handlers(root, source, violations);
    }
}

impl Sig34C {
    fn find_signal_handlers(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // A handler is a function this file registers (signal/sigaction,
        // resolved by declaration), never a function that merely has a
        // handler-shaped signature: `setup_signals(int verbose)` isn't one.
        let handlers = RegisteredHandlers::collect(node, source).signal_handler_names();
        if handlers.is_empty() {
            return;
        }
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            let Some(declarator) = func.child_by_field_name("declarator") else {
                continue;
            };
            if !handlers.contains(&get_identifier_from_declarator(&declarator, source)) {
                continue;
            }
            let param_name = self
                .signal_param_name(&declarator, source)
                .unwrap_or_default();
            if let Some(body) = func.child_by_field_name("body") {
                self.check_for_signal_calls(&body, source, &param_name, violations);
            }
        }
    }

    /// The name of a handler's first parameter: the signal number, for both
    /// `void h(int sig)` and `void h(int sig, siginfo_t *, void *)`.
    fn signal_param_name(&self, declarator: &Node, source: &str) -> Option<String> {
        let first = query::find_descendants_of_kind(*declarator, "parameter_declaration")
            .into_iter()
            .next()?;
        first
            .child_by_field_name("declarator")
            .map(|d| get_identifier_from_declarator(&d, source))
    }

    fn check_for_signal_calls(
        &self,
        node: &Node,
        source: &str,
        handler_param: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);
                if func_name == "signal" {
                    // SIG34-C-EX1: "For implementations with persistent
                    // signal handlers, it is safe for a handler to modify
                    // the behavior of its OWN signal" -- i.e. signal(sig, ...)
                    // where `sig` is this handler's own signal-number
                    // parameter, not some other/unrelated signal.
                    if self.is_self_signal_modification(&n, handler_param, source) {
                        continue;
                    }
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: "signal() called from within signal handler; this is not safe"
                            .to_string(),
                        file_path: String::new(),
                        line: n.start_position().row + 1,
                        column: n.start_position().column + 1,
                        suggestion: None,
                        requires_manual_review: None,
                    });
                }
            }
        }
    }

    /// True if `call` is `signal(handler_param, ...)` (the handler
    /// modifying its OWN signal, not an unrelated one) AND that call is
    /// guarded by a platform-conditional preprocessor block (e.g. `#if
    /// !defined(_WIN32)`). EX1 is conditioned on "implementations with
    /// persistent signal handlers" -- portable code can't assume that
    /// unconditionally (ISO C / Windows reset to SIG_DFL before invoking
    /// the handler, reopening the exact race this rule guards against), so
    /// the preprocessor guard is what actually establishes the exception's
    /// precondition. An unguarded self-modification (verified against this
    /// codebase's own testcases_self_reregister.c/testcases_reset_
    /// disposition.c, which explicitly test this as a violation) stays
    /// flagged.
    fn is_self_signal_modification(&self, call: &Node, handler_param: &str, source: &str) -> bool {
        let Some(args) = call.child_by_field_name("arguments") else {
            return false;
        };
        let mut cursor = args.walk();
        let Some(first_arg) = args.named_children(&mut cursor).next() else {
            return false;
        };
        if get_node_text(&first_arg, source).trim() != handler_param {
            return false;
        }

        let mut current = call.parent();
        while let Some(n) = current {
            if matches!(n.kind(), "preproc_if" | "preproc_ifdef") {
                return true;
            }
            if n.kind() == "function_definition" {
                break;
            }
            current = n.parent();
        }
        false
    }
}
