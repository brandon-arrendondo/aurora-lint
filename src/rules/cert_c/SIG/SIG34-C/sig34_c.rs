// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::{
    declares_static, get_identifier_from_declarator, get_node_text, static_macro_names_in_scope,
};
use crate::utility::cert_c::signal_handlers::RegisteredHandlers;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::sync::Arc;
use tree_sitter::Node;

pub struct Sig34C {
    /// The prescan's context: handlers declared only in a header, and
    /// handlers another file registers (see
    /// `ProjectContext::signal_handlers_registered_elsewhere`).
    project: RefCell<Option<ProjectContext>>,
    /// The run's settings: whether the environment declares persistent
    /// signal handlers (`signal_handlers_persistent`), which EX1 needs.
    settings: RefCell<Arc<AnalysisSettings>>,
}

impl Sig34C {
    pub fn new() -> Self {
        Self {
            project: RefCell::new(None),
            settings: RefCell::default(),
        }
    }
}

impl Default for Sig34C {
    fn default() -> Self {
        Self::new()
    }
}

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

    fn cert_id(&self) -> &'static str {
        self.rule_id()
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        *self.settings.borrow_mut() = Arc::clone(settings);
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.clone());
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
        // Another file may register it: then only an external definition is
        // the function that file names.
        let project = self.project.borrow();
        let handlers =
            RegisteredHandlers::collect_in(node, source, project.as_ref()).signal_handler_names();
        let elsewhere = project
            .as_ref()
            .map(|p| p.signal_handlers_registered_elsewhere.clone())
            .unwrap_or_default();
        if handlers.is_empty() && elsewhere.is_empty() {
            return;
        }
        let static_macros = project
            .as_ref()
            .map(|p| static_macro_names_in_scope(source, &p.static_macro_names))
            .unwrap_or_default();
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            let Some(declarator) = func.child_by_field_name("declarator") else {
                continue;
            };
            let name = get_identifier_from_declarator(&declarator, source);
            let registered = handlers.contains(&name)
                || (elsewhere.contains(&name) && !declares_static(&func, source, &static_macros));
            if !registered {
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
        let persistent = self.settings.borrow().flag("signal_handlers_persistent");
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);
                if func_name == "signal" {
                    // SIG34-C-EX1: "For implementations with persistent
                    // signal handlers, it is safe for a handler to modify
                    // the behavior of its own signal" -- signal(sig, ...)
                    // where `sig` is this handler's own signal-number
                    // parameter. Persistence is implementation-defined (C11
                    // 7.14.1.1p3, and POSIX leaves it so too), so only a
                    // declared environment establishes it: an `#if` around
                    // the call, `!defined(_WIN32)` in CERT's example, names
                    // a platform, not a persistent one.
                    if persistent && self.is_self_signal_modification(&n, handler_param, source) {
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

    /// True if `call` is `signal(handler_param, ...)`: the handler
    /// modifying its own signal, not an unrelated one.
    fn is_self_signal_modification(&self, call: &Node, handler_param: &str, source: &str) -> bool {
        let Some(args) = call.child_by_field_name("arguments") else {
            return false;
        };
        let mut cursor = args.walk();
        let Some(first_arg) = args.named_children(&mut cursor).next() else {
            return false;
        };
        get_node_text(&first_arg, source).trim() == handler_param
    }
}
