// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! WIN00-C: Be specific when dynamically loading libraries
//!
//! Using LoadLibrary() without specifying search paths can allow DLL hijacking attacks.

use crate::settings::IntFacts;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::Arc;

use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval::{
    merged_macro_aliases, merged_macro_constants, resolve_macro_alias, try_evaluate_text_public,
    MacroConstantMap,
};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::call_roles;
use lang_parsing_substrate::query;

/// `LoadLibraryEx` flag values (winbase.h / libloaderapi.h), so a flags
/// argument is judged by the bits it carries, not by how it is spelled.
const LOAD_LIBRARY_FLAGS: &[(&str, u64)] = &[
    ("DONT_RESOLVE_DLL_REFERENCES", 0x1),
    ("LOAD_LIBRARY_AS_DATAFILE", 0x2),
    ("LOAD_WITH_ALTERED_SEARCH_PATH", 0x8),
    ("LOAD_IGNORE_CODE_AUTHZ_LEVEL", 0x10),
    ("LOAD_LIBRARY_AS_IMAGE_RESOURCE", 0x20),
    ("LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE", 0x40),
    ("LOAD_LIBRARY_REQUIRE_SIGNED_TARGET", 0x80),
    ("LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR", 0x100),
    ("LOAD_LIBRARY_SEARCH_APPLICATION_DIR", 0x200),
    ("LOAD_LIBRARY_SEARCH_USER_DIRS", 0x400),
    ("LOAD_LIBRARY_SEARCH_SYSTEM32", 0x800),
    ("LOAD_LIBRARY_SEARCH_DEFAULT_DIRS", 0x1000),
    ("LOAD_LIBRARY_SAFE_CURRENT_DIRS", 0x2000),
    ("LOAD_LIBRARY_SEARCH_SYSTEM32_NO_FORWARDER", 0x4000),
    ("LOAD_LIBRARY_OS_INTEGRITY_CONTINUITY", 0x8000),
];

/// The flags that make a `LoadLibraryEx` call specific about where the DLL
/// comes from: every `LOAD_LIBRARY_SEARCH_*` flag, and
/// `LOAD_WITH_ALTERED_SEARCH_PATH` (only meaningful with a fully qualified
/// path, so it declares one).
const SEARCH_PATH_CONTROL_BITS: u64 = 0x8 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000 | 0x4000;

pub struct Win00C {
    /// `ProjectContext::macro_aliases` and `macro_constants`: a flags macro
    /// is usually defined in a header.
    project_aliases: RefCell<Arc<HashMap<String, String>>>,
    project_constants: RefCell<Arc<MacroConstantMap>>,
    /// The integer data model the settings credit: which limit macros and
    /// `sizeof` values are constants.
    data_model: Cell<IntFacts>,
}

impl Win00C {
    pub fn new() -> Self {
        Self {
            project_aliases: RefCell::new(Arc::new(HashMap::new())),
            project_constants: RefCell::new(Arc::new(HashMap::new())),
            data_model: Cell::new(IntFacts::default()),
        }
    }
}

impl Default for Win00C {
    fn default() -> Self {
        Self::new()
    }
}

/// This file's object-like macros whose value is a flags expression over
/// `LoadLibraryEx` flag names, literals and each other
/// (`#define DLL_LOAD_FLAGS (LOAD_LIBRARY_AS_DATAFILE | 0)`), evaluated with
/// the flag values known. The shared constant collector cannot value these:
/// it does not know the Windows names. A name defined differently in
/// different branches is left out, since which one is compiled is unknown.
fn file_flag_macros(source: &str) -> MacroConstantMap {
    let mut bodies: HashMap<String, Option<String>> = HashMap::new();
    for line in source.lines() {
        let Some(rest) = line.trim_start().strip_prefix('#') else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix("define") else {
            continue;
        };
        if !rest.starts_with([' ', '\t']) {
            continue;
        }
        let rest = rest.trim_start();
        let name_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let (name, body) = rest.split_at(name_len);
        // A function-like macro opens its parameter list right after the
        // name; only object-like ones have a flags value.
        if name.is_empty() || body.starts_with('(') {
            continue;
        }
        let body = body.split("/*").next().unwrap_or(body);
        let body = body.split("//").next().unwrap_or(body).trim().to_string();
        bodies
            .entry(name.to_string())
            .and_modify(|seen| {
                if seen.as_deref() != Some(body.as_str()) {
                    *seen = None;
                }
            })
            .or_insert(Some(body));
    }
    let mut known: MacroConstantMap = LOAD_LIBRARY_FLAGS
        .iter()
        .map(|(name, value)| (name.to_string(), *value as i64))
        .collect();
    let mut out = MacroConstantMap::new();
    // A few rounds settle a chain of flag macros defined in terms of each
    // other, in any order.
    for _ in 0..4 {
        let mut changed = false;
        for (name, body) in &bodies {
            let Some(body) = body else { continue };
            if known.contains_key(name) {
                continue;
            }
            if let Some(value) = flags_text_value(body, &known) {
                known.insert(name.clone(), value);
                out.insert(name.clone(), value);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    out
}

/// The value of a flags expression written as text: `|`-joined parts, each a
/// literal, a known name or a parenthesized flags expression. The shared
/// constant evaluator has no `|`, and flags are built with nothing else.
fn flags_text_value(text: &str, known: &MacroConstantMap) -> Option<i64> {
    let mut text = text.trim();
    while let Some(inner) = text.strip_prefix('(').and_then(|t| t.strip_suffix(')')) {
        let mut depth = 0i32;
        if inner.chars().any(|c| {
            depth += match c {
                '(' => 1,
                ')' => -1,
                _ => 0,
            };
            depth < 0
        }) {
            break;
        }
        text = inner.trim();
    }
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, c) in text.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            '|' if depth == 0 => {
                parts.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if parts.is_empty() {
        return try_evaluate_text_public(text, known);
    }
    parts.push(&text[start..]);
    parts
        .into_iter()
        .map(|part| flags_text_value(part, known))
        .try_fold(0i64, |acc, part| part.map(|v| acc | v))
}

/// What this file's macros say, for evaluating a flags argument.
struct FlagMacros {
    aliases: HashMap<String, String>,
    constants: MacroConstantMap,
}

impl CertRule for Win00C {
    fn set_analysis_settings(&self, settings: &std::sync::Arc<crate::settings::AnalysisSettings>) {
        self.data_model.set(settings.facts);
    }

    fn rule_id(&self) -> &'static str {
        "WIN00-C"
    }

    fn description(&self) -> &'static str {
        "Be specific when dynamically loading libraries"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "WIN00-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_aliases.borrow_mut() = context.macro_aliases.clone();
        *self.project_constants.borrow_mut() = context.macro_constants.clone();
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut constants = merged_macro_constants(
            &self.project_constants.borrow(),
            node,
            source,
            self.data_model.get(),
        );
        constants.extend(file_flag_macros(source));
        let macros = FlagMacros {
            aliases: merged_macro_aliases(&self.project_aliases.borrow(), node, source),
            constants,
        };
        self.check_node(node, source, &macros, violations);
    }
}

impl Win00C {
    /// True when the flags argument to `LoadLibraryEx` provably carries no
    /// search-path control: its value is known (literals, `|`, and names
    /// that resolve to a flag or a constant) and has none of
    /// [`SEARCH_PATH_CONTROL_BITS`]. A variable, a field, a call, or a name
    /// no definition resolves is left alone: the flag may well be in it.
    fn flags_provably_lack_search_path(flags: &Node, source: &str, macros: &FlagMacros) -> bool {
        Self::flags_value(flags, source, macros)
            .is_some_and(|value| value & SEARCH_PATH_CONTROL_BITS == 0)
    }

    /// The value of a flags expression built from integer literals, `|`,
    /// parentheses and names, or `None` when any part cannot be known. A
    /// name is followed through `#define ALIAS target` chains to a
    /// `LoadLibraryEx` flag or a macro constant; its spelling alone decides
    /// nothing, so `#define MY_SEARCH LOAD_LIBRARY_SEARCH_SYSTEM32` is a
    /// search-path flag.
    fn flags_value(flags: &Node, source: &str, macros: &FlagMacros) -> Option<u64> {
        match flags.kind() {
            "number_literal" => {
                try_evaluate_text_public(get_node_text(flags, source), &HashMap::new())
                    .and_then(|v| u64::try_from(v).ok())
            }
            "identifier" => {
                let name = resolve_macro_alias(&macros.aliases, get_node_text(flags, source));
                LOAD_LIBRARY_FLAGS
                    .iter()
                    .find(|(flag, _)| *flag == name)
                    .map(|(_, value)| *value)
                    .or_else(|| {
                        macros
                            .constants
                            .get(name)
                            .and_then(|v| u64::try_from(*v).ok())
                    })
            }
            "parenthesized_expression" => flags
                .named_child(0)
                .and_then(|inner| Self::flags_value(&inner, source, macros)),
            "binary_expression" => {
                let operator = flags.child_by_field_name("operator")?;
                if get_node_text(&operator, source) != "|" {
                    return None;
                }
                let left = Self::flags_value(&flags.child_by_field_name("left")?, source, macros)?;
                let right =
                    Self::flags_value(&flags.child_by_field_name("right")?, source, macros)?;
                Some(left | right)
            }
            _ => None,
        }
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        macros: &FlagMacros,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            let Some(func_node) = n.child_by_field_name("function") else {
                continue;
            };
            let func_name = get_node_text(&func_node, source).trim();

            // `LoadLibrary` and its `A`/`W` entry points search the default
            // DLL path unconditionally. `LoadLibraryEx` only does so when
            // its flags say nothing about the search path.
            let unspecific = if call_roles::is_win32_api(func_name, "LoadLibrary") {
                true
            } else if call_roles::is_win32_api(func_name, "LoadLibraryEx") {
                n.child_by_field_name("arguments")
                    .and_then(|args| args.named_child(2))
                    .is_some_and(|flags| {
                        Self::flags_provably_lack_search_path(&flags, source, macros)
                    })
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
