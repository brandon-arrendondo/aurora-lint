// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! FLP36-C: Preserve precision when converting integral values to floating-point type
//!
//! This rule detects conversions from integer types to floating-point types that may
//! lose precision because the floating-point type cannot represent all integer values.
//!
//! VIOLATIONS:
//! - float approx = long_value;      // long to float may lose precision
//! - float f = int64_value;          // int64_t to float may lose precision
//!
//! COMPLIANT:
//! - double approx = long_value;     // double has sufficient precision
//! - With precision assertion checking before conversion

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::sync::Arc;
use tree_sitter::Node;

#[derive(Default)]
pub struct Flp36C {
    /// The run's policy and environment settings: whether an
    /// NDEBUG-strippable assert counts as a precision check
    /// (`assert_is_guard`).
    settings: RefCell<Arc<AnalysisSettings>>,
}

impl CertRule for Flp36C {
    fn rule_id(&self) -> &'static str {
        "FLP36-C"
    }

    fn description(&self) -> &'static str {
        "Preserve precision when converting integral values to floating-point type"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "FLP36-C"
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        *self.settings.borrow_mut() = Arc::clone(settings);
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        // Check for assignments/declarations that might lose precision
        query::find_descendants_of_kinds(*node, &["assignment_expression", "init_declarator"])
            .into_iter()
            .filter_map(|n| self.check_int_to_float_conversion(&n, source))
            .collect()
    }
}

impl Flp36C {
    /// Check if an assignment/declaration converts int to float without precision check
    fn check_int_to_float_conversion(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Check if there's precision checking in the function
        if self.has_precision_checking(node, source) {
            return None;
        }

        // Check if this is actually a long -> float conversion
        if !self.is_long_to_float_conversion(node, source) {
            return None;
        }

        // If no precision checking, report as potential violation
        let start_point = node.start_position();

        Some(RuleViolation {
            rule_id: "FLP36-C".to_string(),
            severity: Severity::Medium,
            message: "Potential precision loss in integer to floating-point conversion".to_string(),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(
                "Ensure target floating-point type has sufficient precision (use assert with PRECISION macro or use double instead of float)".to_string()
            ),
            requires_manual_review: None,
        })
    }

    /// Check if this is a long -> float conversion
    fn is_long_to_float_conversion(&self, node: &Node, source: &str) -> bool {
        // Get the declaration context
        if node.kind() == "init_declarator" {
            if let Some(parent) = node.parent() {
                let decl_text = ast_utils::get_node_text(&parent, source);
                // Check if target is float (not double)
                if decl_text.contains("float") && !decl_text.contains("double") {
                    // Check if source is a long variable
                    if let Some(value) = node.child_by_field_name("value") {
                        let value_text = ast_utils::get_node_text(&value, source);
                        // Look for the long variable in scope
                        if self.is_long_variable(node, &value_text, source) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if a variable name refers to a long type variable
    fn is_long_variable(&self, node: &Node, var_name: &str, source: &str) -> bool {
        let var_name = var_name.trim();
        // Sanitized (comments/string/char literals blanked) so a comment or
        // string literal mentioning "long" and the variable name elsewhere
        // in the file can't spoof a false "is long" match — this only
        // affects whether the violation is TRIGGERED, but a spurious trigger
        // is still an incorrect finding worth preventing.
        let mut root = *node;
        while let Some(p) = root.parent() {
            root = p;
        }
        let sanitized_source = ast_utils::get_sanitized_node_text(&root, source);
        // Search source for declaration of this variable as long
        for line in sanitized_source.lines() {
            if (line.contains("long int") || (line.contains("long") && !line.contains("double")))
                && line.contains(var_name)
            {
                return true;
            }
        }
        false
    }

    /// Check if there's precision validation in the function
    fn has_precision_checking(&self, node: &Node, source: &str) -> bool {
        // Find the containing function body
        let function_body = self.get_containing_function_body(node);
        let body = match function_body {
            Some(b) => b,
            None => return false,
        };

        // Sanitized so a comment/string literal in the function can't spoof
        // a precision-check pattern and silently suppress a genuine
        // precision-loss violation.
        let body_text = ast_utils::get_sanitized_node_text(&body, source);

        // Look for precision checking patterns
        if body_text.contains("PRECISION") {
            return true;
        }

        if body_text.contains("DBL_MANT_DIG") || body_text.contains("FLT_MANT_DIG") {
            return true;
        }

        // An `assert(x <= LONG_MAX ...)` counts only when the policy credits
        // an NDEBUG-strippable assert (`assert_is_guard`); the strict policy
        // reads the release configuration, where it checks nothing
        // (ADR-0010 D5).
        if self.settings.borrow().flag("assert_is_guard")
            && body_text.contains("assert")
            && body_text.contains("LONG_MAX")
        {
            return true;
        }

        // An assert over platform constants checks the platform, whatever
        // the build, in the spirit of CERT's compliant solution
        // (`flp36_constant_assert_is_guard`).
        if self
            .settings
            .borrow()
            .flag("flp36_constant_assert_is_guard")
            && has_constant_assert(&body, source)
        {
            return true;
        }

        // Using double instead of float is compliant
        if body_text.contains("double") && !body_text.contains("float") {
            return true;
        }

        false
    }

    /// Get the containing function body
    fn get_containing_function_body<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = node.parent();

        while let Some(n) = current {
            if n.kind() == "compound_statement" {
                if let Some(parent) = n.parent() {
                    if parent.kind() == "function_definition" {
                        return Some(n);
                    }
                }
            }
            current = n.parent();
        }

        None
    }
}

/// Whether `body` holds an `assert` that checks the platform: a comparison
/// whose operands are fixed at compile time from what this file can see
/// (literals, `sizeof`, the standard limit macros, macros the file defines,
/// and arithmetic over them), at least one of which is a standard integer
/// limit or floating-point precision macro, so the check bears on a
/// conversion between the two. A name the file cannot see may be a global,
/// so it does not count, and neither does a bare constant (`assert(1)`).
fn has_constant_assert(body: &Node, source: &str) -> bool {
    let mut stack = vec![*body];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression"
            && node.child_by_field_name("function").is_some_and(|f| {
                f.kind() == "identifier" && ast_utils::get_node_text(&f, source) == "assert"
            })
            && node
                .child_by_field_name("arguments")
                .and_then(|args| args.named_child(0))
                .is_some_and(|cond| is_platform_check(&cond, source))
        {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

/// A comparison, or a logical combination of comparisons, over platform
/// constants that names a standard limit.
fn is_platform_check(node: &Node, source: &str) -> bool {
    let mut names_limit = false;
    is_constant_comparison(node, source, &mut names_limit) && names_limit
}

fn is_constant_comparison(node: &Node, source: &str, names_limit: &mut bool) -> bool {
    match node.kind() {
        "parenthesized_expression" => node
            .named_child(0)
            .is_some_and(|inner| is_constant_comparison(&inner, source, names_limit)),
        "binary_expression" => {
            let op = ast_utils::get_binary_operator(node, source).unwrap_or_default();
            let (Some(l), Some(r)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return false;
            };
            match op {
                "&&" | "||" => {
                    is_constant_comparison(&l, source, names_limit)
                        && is_constant_comparison(&r, source, names_limit)
                }
                "<" | "<=" | ">" | ">=" | "==" | "!=" => {
                    is_platform_constant(&l, source, names_limit)
                        && is_platform_constant(&r, source, names_limit)
                }
                _ => false,
            }
        }
        _ => false,
    }
}

/// An operand fixed at compile time from what this file can see.
fn is_platform_constant(node: &Node, source: &str, names_limit: &mut bool) -> bool {
    match node.kind() {
        "number_literal" | "sizeof_expression" => true,
        "parenthesized_expression" => node
            .named_child(0)
            .is_some_and(|inner| is_platform_constant(&inner, source, names_limit)),
        "cast_expression" => node
            .child_by_field_name("value")
            .is_some_and(|v| is_platform_constant(&v, source, names_limit)),
        "binary_expression" => {
            let op = ast_utils::get_binary_operator(node, source).unwrap_or_default();
            matches!(
                op,
                "+" | "-" | "*" | "/" | "%" | "<<" | ">>" | "&" | "|" | "^"
            ) && node
                .child_by_field_name("left")
                .is_some_and(|l| is_platform_constant(&l, source, names_limit))
                && node
                    .child_by_field_name("right")
                    .is_some_and(|r| is_platform_constant(&r, source, names_limit))
        }
        "identifier" => {
            let name = ast_utils::get_node_text(node, source);
            if is_standard_limit_macro(name) {
                *names_limit = true;
                true
            } else {
                ast_utils::is_defined_macro_name(name, source)
            }
        }
        _ => false,
    }
}

/// A limit or precision macro of `<limits.h>`, `<stdint.h>` or `<float.h>`
/// (C11 5.2.4.2, 7.20.2, 7.20.3): reserved names, so the spelling is the
/// identity.
fn is_standard_limit_macro(name: &str) -> bool {
    const INTEGER: &[&str] = &[
        "CHAR_BIT",
        "SCHAR_MIN",
        "SCHAR_MAX",
        "UCHAR_MAX",
        "CHAR_MIN",
        "CHAR_MAX",
        "SHRT_MIN",
        "SHRT_MAX",
        "USHRT_MAX",
        "INT_MIN",
        "INT_MAX",
        "UINT_MAX",
        "LONG_MIN",
        "LONG_MAX",
        "ULONG_MAX",
        "LLONG_MIN",
        "LLONG_MAX",
        "ULLONG_MAX",
        "INTMAX_MIN",
        "INTMAX_MAX",
        "UINTMAX_MAX",
        "INTPTR_MIN",
        "INTPTR_MAX",
        "UINTPTR_MAX",
        "PTRDIFF_MIN",
        "PTRDIFF_MAX",
        "SIZE_MAX",
    ];
    if INTEGER.contains(&name) || name == "FLT_RADIX" {
        return true;
    }
    if let Some(rest) = name
        .strip_prefix("FLT_")
        .or_else(|| name.strip_prefix("DBL_"))
        .or_else(|| name.strip_prefix("LDBL_"))
    {
        return matches!(rest, "MANT_DIG" | "DIG" | "MAX");
    }
    // INTn_MAX, INT_LEASTn_MIN, UINT_FASTn_MAX and the rest of <stdint.h>.
    let core = name.strip_prefix('U').unwrap_or(name);
    let Some(core) = core.strip_prefix("INT") else {
        return false;
    };
    let core = core
        .strip_prefix("_LEAST")
        .or_else(|| core.strip_prefix("_FAST"))
        .unwrap_or(core);
    let Some((width, limit)) = core.split_once('_') else {
        return false;
    };
    !width.is_empty() && width.bytes().all(|b| b.is_ascii_digit()) && matches!(limit, "MIN" | "MAX")
}
