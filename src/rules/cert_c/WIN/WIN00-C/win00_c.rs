// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! WIN00-C: Be specific when dynamically loading libraries
//!
//! Using LoadLibrary() without specifying search paths can allow DLL hijacking attacks.

use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::call_roles;
use lang_parsing_substrate::query;

pub struct Win00C;

impl CertRule for Win00C {
    fn rule_id(&self) -> &'static str {
        "WIN00-C"
    }

    fn description(&self) -> &'static str {
        "Be specific when dynamically loading libraries"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "WIN00-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Win00C {
    /// Search-path controls that make a `LoadLibraryEx` call specific about
    /// where the DLL comes from: any `LOAD_LIBRARY_SEARCH_*` flag, or
    /// `LOAD_WITH_ALTERED_SEARCH_PATH` (which is only meaningful with a
    /// fully qualified path, so it declares one).
    fn flags_control_search_path(flags_text: &str) -> bool {
        flags_text.contains("LOAD_LIBRARY_SEARCH_")
            || flags_text.contains("LOAD_WITH_ALTERED_SEARCH_PATH")
    }

    /// True when the flags argument to `LoadLibraryEx` provably carries no
    /// search-path control: a constant expression built only from integer
    /// literals and `|`-joined flag macros (`ALL_CAPS` identifiers), none
    /// of which is one. A variable (`flags`), a field or a call is left
    /// alone -- the flag may well be in it, and the rule cannot read it.
    fn flags_provably_lack_search_path(flags: &Node, source: &str) -> bool {
        match flags.kind() {
            "number_literal" => true,
            "identifier" => {
                let text = get_node_text(flags, source);
                let is_flag_macro = text
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                    && text.chars().any(|c| c.is_ascii_uppercase());
                is_flag_macro && !Self::flags_control_search_path(text)
            }
            "parenthesized_expression" => flags
                .named_child(0)
                .is_some_and(|inner| Self::flags_provably_lack_search_path(&inner, source)),
            "binary_expression" => {
                let (Some(left), Some(right)) = (
                    flags.child_by_field_name("left"),
                    flags.child_by_field_name("right"),
                ) else {
                    return false;
                };
                Self::flags_provably_lack_search_path(&left, source)
                    && Self::flags_provably_lack_search_path(&right, source)
            }
            _ => false,
        }
    }

    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            let Some(func_node) = n.child_by_field_name("function") else {
                continue;
            };
            let func_name = get_node_text(&func_node, source).trim();

            // `LoadLibrary` and its `A`/`W` entry points search the default
            // DLL path unconditionally. `LoadLibraryEx` only does so when
            // its flags say nothing about the search path (task 1130).
            let unspecific = if call_roles::is_win32_api(func_name, "LoadLibrary") {
                true
            } else if call_roles::is_win32_api(func_name, "LoadLibraryEx") {
                n.child_by_field_name("arguments")
                    .and_then(|args| args.named_child(2))
                    .is_some_and(|flags| Self::flags_provably_lack_search_path(&flags, source))
            } else {
                false
            };
            if !unspecific {
                continue;
            }

            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                line: n.start_position().row + 1,
                column: n.start_position().column + 1,
                file_path: String::new(),
                message: format!(
                    "{}() loads a DLL through the default search path, which enables DLL hijacking: \
                     an attacker could place a malicious DLL on that path.",
                    func_name
                ),
                suggestion: Some(
                    "Use LoadLibraryEx() with explicit search flags like LOAD_LIBRARY_SEARCH_APPLICATION_DIR \
                    or LOAD_LIBRARY_SEARCH_SYSTEM32 to control DLL search paths.".to_string()
                ),
                requires_manual_review: None,
            });
        }
    }
}
