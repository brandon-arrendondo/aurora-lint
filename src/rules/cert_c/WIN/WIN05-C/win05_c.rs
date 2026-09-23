// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! WIN05-C: Do not violate least privilege when creating processes or accessing registry
//!
//! Detects two patterns:
//! 1. CreateProcess with unquoted paths containing spaces (path interception)
//! 2. Registry operations using HKEY_LOCAL_MACHINE (excessive privilege)
//!
//! The registry check follows the root-key handle through project wrappers:
//! `GetRegDwordValue(HKEY_LOCAL_MACHINE, ...)` whose body forwards its first
//! parameter to `RegOpenKeyExA` is the same HKLM access as the direct call,
//! and requiring the literal `HKEY_LOCAL_MACHINE` at the `RegOpenKeyEx*` site
//! missed every such wrapper. The walk is bounded and follows
//! `FunctionSummary::param_passthroughs` for function hops and
//! `macro_forwarding_target` for a function-like macro hop, so a chain like
//! ventoy's `ReadRegistryKey32(root, key)` -> `GetRegistryKey32(root, ...)`
//! (macro) -> `_GetRegistryKey(key_root, ...)` -> `RegOpenKeyExA(key_root, ...)`
//! resolves. The argument itself is resolved through object-like aliases
//! (`#define REGKEY_HKLM HKEY_LOCAL_MACHINE`) the same way.

use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval::{merged_macro_aliases, resolve_macro_alias};
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::macro_expand::{macro_forwarding_target, FunctionMacro};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

/// Functions that take a command line string that should have quoted paths.
/// (function_name, argument_index of lpCommandLine, 0-based)
const CREATE_PROCESS_FUNCTIONS: &[(&str, usize)] = &[
    ("CreateProcessA", 1),
    ("CreateProcessW", 1),
    ("CreateProcessAsUserA", 2),
    ("CreateProcessAsUserW", 2),
];

/// Registry functions whose first argument is a root key handle.
const REGISTRY_FUNCTIONS: &[&str] = &[
    "RegCreateKeyA",
    "RegCreateKeyW",
    "RegCreateKeyExA",
    "RegCreateKeyExW",
    "RegOpenKeyExA",
    "RegOpenKeyExW",
];

/// SHRegCreate functions that use SHREGSET_HKLM flag (arg index 4).
const SHREG_CREATE_FUNCTIONS: &[&str] = &["SHRegCreateUSKeyA", "SHRegCreateUSKeyW"];

/// SHRegOpen functions where fIgnoreHKCU=TRUE (arg index 4) means HKLM.
const SHREG_OPEN_FUNCTIONS: &[&str] = &["SHRegOpenUSKeyA", "SHRegOpenUSKeyW"];

/// Root-key handles that require administrator privileges to write.
const PRIVILEGED_ROOT_KEYS: &[&str] = &["HKEY_LOCAL_MACHINE", "HKEY_CLASSES_ROOT"];

/// How many wrapper hops to follow from the call site before giving up. A
/// function hop and a macro hop each count as one; ventoy's deepest chain
/// (function -> macro -> function -> `RegOpenKeyExA`) needs three.
const MAX_WRAPPER_DEPTH: usize = 4;

pub struct Win05C {
    /// Prescan function summaries: `param_passthroughs` is the edge a wrapper
    /// hop follows (handle from `set_project_context`, see the catalog's
    /// "Cross-file project context" section).
    function_summaries: RefCell<Arc<HashMap<String, FunctionSummary>>>,
    /// Project function-like macros, for a forwarding-macro hop.
    function_macros: RefCell<Arc<HashMap<String, FunctionMacro>>>,
    /// Project object-like aliases (`#define REGKEY_HKLM HKEY_LOCAL_MACHINE`);
    /// merged with the scanned file's own in `check_node`.
    macro_aliases: RefCell<Arc<HashMap<String, String>>>,
}

impl Default for Win05C {
    fn default() -> Self {
        Self::new()
    }
}

impl Win05C {
    pub fn new() -> Self {
        Self {
            function_summaries: RefCell::new(Arc::new(HashMap::new())),
            function_macros: RefCell::new(Arc::new(HashMap::new())),
            macro_aliases: RefCell::new(Arc::new(HashMap::new())),
        }
    }

    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let aliases = merged_macro_aliases(&self.macro_aliases.borrow(), node, source);
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_call(&call, source, &aliases, violations);
        }
    }

    /// Does argument `arg_idx` of a call to `callee` end up as the root-key
    /// argument of one of `REGISTRY_FUNCTIONS`, within `MAX_WRAPPER_DEPTH`
    /// hops? Returns the registry function it lands on. A function hop
    /// follows the callee's `param_passthroughs` (MAY-forward: a wrapper that
    /// opens the key only on some path still opens it); a macro hop follows
    /// `macro_forwarding_target`'s positional map. `active` breaks cycles.
    fn root_key_sink(
        &self,
        callee: &str,
        arg_idx: usize,
        depth: usize,
        active: &mut HashSet<String>,
    ) -> Option<String> {
        if REGISTRY_FUNCTIONS.contains(&callee) {
            return (arg_idx == 0).then(|| callee.to_string());
        }
        if depth >= MAX_WRAPPER_DEPTH || !active.insert(callee.to_string()) {
            return None;
        }
        let mut found = None;
        if let Some(summary) = self.function_summaries.borrow().get(callee) {
            if let Some(edges) = summary.param_passthroughs.get(&arg_idx) {
                for (next, next_idx) in edges {
                    found = self.root_key_sink(next, *next_idx, depth + 1, active);
                    if found.is_some() {
                        break;
                    }
                }
            }
        }
        if found.is_none() {
            let target = macro_forwarding_target(&self.function_macros.borrow(), callee);
            if let Some((next, param_map)) = target {
                for (next_idx, mapped) in param_map.iter().enumerate() {
                    if *mapped == Some(arg_idx) {
                        found = self.root_key_sink(&next, next_idx, depth + 1, active);
                        if found.is_some() {
                            break;
                        }
                    }
                }
            }
        }
        active.remove(callee);
        found
    }

    fn check_call(
        &self,
        node: &Node,
        source: &str,
        aliases: &HashMap<String, String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let func_name = match node.child_by_field_name("function") {
            Some(f) => get_node_text(&f, source).to_string(),
            None => return,
        };

        let args = match node.child_by_field_name("arguments") {
            Some(a) => a,
            None => return,
        };

        // Check CreateProcess for unquoted paths
        for &(cp_func, arg_idx) in CREATE_PROCESS_FUNCTIONS {
            if func_name == cp_func {
                if let Some(arg) = self.get_nth_argument(&args, arg_idx) {
                    self.check_unquoted_path(&arg, source, &func_name, violations);
                }
                return;
            }
        }

        // Check registry functions -- and project wrappers around them -- for
        // a privileged root key. Every argument position is a candidate: a
        // wrapper is free to take the root key anywhere in its own signature.
        let mut arg_idx = 0usize;
        while let Some(arg) = self.get_nth_argument(&args, arg_idx) {
            let spelled = get_node_text(&arg, source).trim();
            let resolved = resolve_macro_alias(aliases, spelled);
            if PRIVILEGED_ROOT_KEYS.contains(&resolved) {
                let mut active = HashSet::new();
                if let Some(sink) = self.root_key_sink(&func_name, arg_idx, 0, &mut active) {
                    let via = if sink == func_name {
                        String::new()
                    } else {
                        format!(" (passed through to '{}')", sink)
                    };
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: format!(
                            "Registry operation '{}' uses '{}'{} which requires administrator \
                             privileges. Use HKEY_CURRENT_USER to follow least privilege.",
                            func_name, resolved, via
                        ),
                        file_path: String::new(),
                        line: arg.start_position().row + 1,
                        column: arg.start_position().column + 1,
                        suggestion: Some(
                            "Use HKEY_CURRENT_USER instead of HKEY_LOCAL_MACHINE".to_string(),
                        ),
                        ..Default::default()
                    });
                    // One finding per call, however many hops it took.
                    break;
                }
            }
            arg_idx += 1;
        }

        // Check SHRegCreate functions for SHREGSET_HKLM flag (5th argument, index 4)
        if SHREG_CREATE_FUNCTIONS.contains(&func_name.as_str()) {
            if let Some(flag_arg) = self.get_nth_argument(&args, 4) {
                let flag_text = get_node_text(&flag_arg, source).trim().to_string();
                if flag_text == "SHREGSET_HKLM" || flag_text.contains("SHREGSET_HKLM") {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: format!(
                            "Registry operation '{}' uses SHREGSET_HKLM which targets \
                             HKEY_LOCAL_MACHINE. Use SHREGSET_HKCU to follow least privilege.",
                            func_name
                        ),
                        file_path: String::new(),
                        line: flag_arg.start_position().row + 1,
                        column: flag_arg.start_position().column + 1,
                        suggestion: Some("Use SHREGSET_HKCU instead of SHREGSET_HKLM".to_string()),
                        ..Default::default()
                    });
                }
            }
        }

        // Check SHRegOpen functions for fIgnoreHKCU=TRUE (5th argument, index 4)
        if SHREG_OPEN_FUNCTIONS.contains(&func_name.as_str()) {
            if let Some(flag_arg) = self.get_nth_argument(&args, 4) {
                let flag_text = get_node_text(&flag_arg, source).trim().to_string();
                if flag_text == "TRUE" || flag_text == "true" || flag_text == "1" {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: format!(
                            "Registry operation '{}' with fIgnoreHKCU=TRUE targets \
                             HKEY_LOCAL_MACHINE. Set to FALSE to follow least privilege.",
                            func_name
                        ),
                        file_path: String::new(),
                        line: flag_arg.start_position().row + 1,
                        column: flag_arg.start_position().column + 1,
                        suggestion: Some(
                            "Set fIgnoreHKCU to FALSE to use HKEY_CURRENT_USER".to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check if a CreateProcess command line argument has an unquoted path with spaces.
    fn check_unquoted_path(
        &self,
        arg: &Node,
        source: &str,
        func_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Only check string literals
        if arg.kind() != "string_literal" {
            return;
        }

        let text = get_node_text(arg, source);
        let content = text.trim_matches('"');

        // Skip NULL or empty
        if content.is_empty() || text == "NULL" || text == "0" {
            return;
        }

        // Check if path contains a space
        if !content.contains(' ') {
            return;
        }

        // Check if the path is properly quoted with escaped quotes
        // Good: "\"C:\\Program Files\\App\" arg1 arg2"
        // Bad:  "C:\\Program Files\\App arg1 arg2"
        if content.starts_with("\\\"") || content.starts_with("\"") {
            return; // Properly quoted
        }

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message: format!(
                "Unquoted path with spaces in '{}' command line. \
                 This allows path interception attacks.",
                func_name
            ),
            file_path: String::new(),
            line: arg.start_position().row + 1,
            column: arg.start_position().column + 1,
            suggestion: Some(
                "Quote the executable path: \\\"C:\\\\Program Files\\\\App\\\" arg1 arg2"
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    fn get_nth_argument<'a>(&self, args: &Node<'a>, index: usize) -> Option<Node<'a>> {
        let mut count = 0;
        for i in 0..args.child_count() {
            if let Some(child) = args.child(i) {
                let kind = child.kind();
                if kind != "(" && kind != ")" && kind != "," {
                    if count == index {
                        return Some(child);
                    }
                    count += 1;
                }
            }
        }
        None
    }
}

impl CertRule for Win05C {
    fn rule_id(&self) -> &'static str {
        "WIN05-C"
    }

    fn description(&self) -> &'static str {
        "Do not violate least privilege when creating processes or accessing registry"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "WIN05-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.function_macros.borrow_mut() = context.function_macros.clone();
        *self.macro_aliases.borrow_mut() = context.macro_aliases.clone();
    }
}
