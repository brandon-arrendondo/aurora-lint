// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! STR38-C: Do not confuse narrow and wide character strings and functions
//!
//! Don't use narrow string functions (strlen, strcpy, etc.) on wide strings (wchar_t*),
//! and don't use wide string functions (wcslen, wcscpy, etc.) on narrow strings (char*).
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! wchar_t wide_str[] = L"hello";
//! strlen(wide_str);  // VIOLATION: strlen on wchar_t
//! ```
//!
//! **Compliant:**
//! ```c
//! wchar_t wide_str[] = L"hello";
//! wcslen(wide_str);  // OK: wcslen on wchar_t
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{get_node_text, resolve_identifier_declarator};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Str38C;

/// Narrow string functions and the argument positions that are strings.
/// The format argument of the printf/scanf members counts: it is a string
/// the function reads with its own width.
const NARROW_FUNCTIONS: &[(&str, &[usize])] = &[
    ("strlen", &[0]),
    ("strcpy", &[0, 1]),
    ("strncpy", &[0, 1]),
    ("strcat", &[0, 1]),
    ("strncat", &[0, 1]),
    ("strcmp", &[0, 1]),
    ("strncmp", &[0, 1]),
    ("strchr", &[0]),
    ("strstr", &[0, 1]),
    ("strdup", &[0]),
    ("sprintf", &[0, 1]),
    ("snprintf", &[0, 2]),
    ("sscanf", &[0, 1]),
];

/// Wide string functions and the argument positions that are strings.
const WIDE_FUNCTIONS: &[(&str, &[usize])] = &[
    ("wcslen", &[0]),
    ("wcscpy", &[0, 1]),
    ("wcsncpy", &[0, 1]),
    ("wcscat", &[0, 1]),
    ("wcsncat", &[0, 1]),
    ("wcscmp", &[0, 1]),
    ("wcsncmp", &[0, 1]),
    ("wcschr", &[0]),
    ("wcsstr", &[0, 1]),
    ("wcsdup", &[0]),
    ("swprintf", &[0, 2]),
    ("swscanf", &[0, 1]),
];

impl CertRule for Str38C {
    fn rule_id(&self) -> &'static str {
        "STR38-C"
    }

    fn description(&self) -> &'static str {
        "Do not confuse narrow and wide character strings and functions"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "STR38-C"
    }

    /// One pass over the calls, in source order. Each string argument's
    /// width comes from its own declaration (resolved at the occurrence, so a
    /// same-named variable in another function or scope never answers), from
    /// a string literal's prefix, or from a cast. Anything else is unknown
    /// and not reported.
    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(v) = self.check_call(&call, source) {
                violations.push(v);
            }
        }
        violations
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Width {
    Wide,   // wchar_t
    Narrow, // char, signed char, unsigned char
}

impl Width {
    fn name(self) -> &'static str {
        match self {
            Width::Wide => "wide",
            Width::Narrow => "narrow",
        }
    }
}

impl Str38C {
    fn check_call(&self, call: &Node, source: &str) -> Option<RuleViolation> {
        let function = call.child_by_field_name("function")?;
        if function.kind() != "identifier" {
            return None;
        }
        let func_name = get_node_text(&function, source);
        let (func_width, positions) =
            if let Some((_, p)) = NARROW_FUNCTIONS.iter().find(|(n, _)| *n == func_name) {
                (Width::Narrow, *p)
            } else if let Some((_, p)) = WIDE_FUNCTIONS.iter().find(|(n, _)| *n == func_name) {
                (Width::Wide, *p)
            } else {
                return None;
            };

        let args = call.child_by_field_name("arguments")?;
        let arg_nodes: Vec<Node> = (0..args.named_child_count())
            .filter_map(|i| args.named_child(i))
            .filter(|n| n.kind() != "comment")
            .collect();

        for &pos in positions {
            let Some(arg) = arg_nodes.get(pos) else {
                continue;
            };
            let Some(arg_width) = self.expr_width(arg, source) else {
                continue;
            };
            if arg_width == func_width {
                continue;
            }
            let arg_text = get_node_text(arg, source);
            return Some(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "{} string function '{}' used on {} string '{}' - type mismatch",
                    if func_width == Width::Narrow {
                        "Narrow"
                    } else {
                        "Wide"
                    },
                    func_name,
                    arg_width.name(),
                    arg_text
                ),
                file_path: String::new(),
                line: call.start_position().row + 1,
                column: call.start_position().column + 1,
                suggestion: Some(format!(
                    "Use {} string function instead (e.g., {})",
                    arg_width.name(),
                    if arg_width == Width::Wide {
                        "wcs* functions"
                    } else {
                        "str* functions"
                    }
                )),
                ..Default::default()
            });
        }
        None
    }

    /// The character width of a string-valued expression, when it can be
    /// read from the code: an identifier declared as one level of pointer or
    /// array of a character type, a string literal, or a cast to a pointer to
    /// a character type.
    fn expr_width(&self, expr: &Node, source: &str) -> Option<Width> {
        let mut e = *expr;
        while e.kind() == "parenthesized_expression" {
            e = e.named_child(0)?;
        }
        match e.kind() {
            "identifier" => {
                let name = get_node_text(&e, source);
                let (decl, declarator) = resolve_identifier_declarator(&e, name, source)?;
                let base = get_node_text(&decl.child_by_field_name("type")?, source);
                if pointer_levels(declarator)? != 1 {
                    return None;
                }
                width_of_char_type(base)
            }
            "string_literal" => literal_width(&e, source),
            "concatenated_string" => {
                let first = e.named_child(0)?;
                literal_width(&first, source)
            }
            "cast_expression" => {
                let ty = e.child_by_field_name("type")?;
                let base = get_node_text(&ty.child_by_field_name("type")?, source);
                let abs = ty.child_by_field_name("declarator")?;
                if abstract_pointer_levels(abs)? != 1 {
                    return None;
                }
                width_of_char_type(base)
            }
            _ => None,
        }
    }
}

/// `L"..."` is wide; an unprefixed or `u8` literal is narrow; `u`/`U`
/// literals are neither (char16_t / char32_t).
fn literal_width(lit: &Node, source: &str) -> Option<Width> {
    let text = get_node_text(lit, source);
    if text.starts_with("L\"") {
        Some(Width::Wide)
    } else if text.starts_with('"') || text.starts_with("u8\"") {
        Some(Width::Narrow)
    } else {
        None
    }
}

fn width_of_char_type(base: &str) -> Option<Width> {
    let norm: String = base.split_whitespace().collect::<Vec<_>>().join(" ");
    match norm.as_str() {
        "wchar_t" => Some(Width::Wide),
        "char" | "signed char" | "unsigned char" => Some(Width::Narrow),
        _ => None,
    }
}

/// Pointer and array levels of a declarator for its name; `None` for a
/// function or function pointer.
fn pointer_levels(declarator: Node) -> Option<usize> {
    let mut d = declarator;
    let mut levels = 0;
    loop {
        match d.kind() {
            "pointer_declarator" | "array_declarator" => levels += 1,
            "function_declarator" => return None,
            "parenthesized_declarator" => {}
            _ => break,
        }
        match d.child_by_field_name("declarator") {
            Some(inner) => d = inner,
            None => match d.named_child(0) {
                Some(inner) if d.kind() == "parenthesized_declarator" => d = inner,
                _ => break,
            },
        }
    }
    Some(levels)
}

/// Pointer and array levels of a cast's abstract declarator (`*`, `**`,
/// `const *`).
fn abstract_pointer_levels(abs: Node) -> Option<usize> {
    let mut d = abs;
    let mut levels = 0;
    loop {
        match d.kind() {
            "abstract_pointer_declarator" | "abstract_array_declarator" => levels += 1,
            "abstract_function_declarator" => return None,
            "abstract_parenthesized_declarator" => {}
            _ => break,
        }
        match d.child_by_field_name("declarator") {
            Some(inner) => d = inner,
            None => break,
        }
    }
    Some(levels)
}
