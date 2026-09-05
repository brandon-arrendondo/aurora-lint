// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! MSC09-C: Character encoding: Use subset of ASCII for safety
//!
//! Characters outside the portable ASCII subset (letters, digits, space, and
//! a small set of punctuation) may be transferred or interpreted differently
//! across locales/national ASCII variants. This rule flags string and
//! character literals that embed a byte with the high bit set (value >= 0x80)
//! -- whether as a raw byte in the source or via a `\xNN` / octal escape --
//! the concrete, statically checkable violation shown in the wiki's own
//! filename example.
//!
//! Note: this does not attempt to track whether externally-supplied strings
//! (e.g. read via `fgets`) are validated against the portable character set
//! before use -- that requires data-flow reasoning and naming heuristics too
//! fragile to generalize safely; see MSC09-C task notes for the specific
//! wiki example this does not cover.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/MSC09-C.+Character+encoding+Use+subset+of+ASCII+for+safety

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Msc09C;

impl Msc09C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Msc09C
    }

    /// Returns true if a hex/octal escape sequence's text encodes a byte
    /// value >= 0x80 (non-ASCII).
    fn escape_is_non_ascii(&self, text: &str) -> bool {
        if let Some(hex) = text.strip_prefix("\\x") {
            if let Ok(v) = u32::from_str_radix(hex, 16) {
                return v >= 0x80;
            }
        } else if text.len() > 1 {
            let rest = &text[1..];
            if !rest.is_empty() && rest.chars().all(|c| ('0'..='7').contains(&c)) {
                if let Ok(v) = u32::from_str_radix(rest, 8) {
                    return v >= 0x80;
                }
            }
        }
        false
    }

    fn check_literal(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            let text = ast_utils::get_node_text(&child, source);
            let flagged = match child.kind() {
                "escape_sequence" => self.escape_is_non_ascii(text),
                "string_content" | "char_content" => text.bytes().any(|b| b >= 0x80),
                _ => false,
            };
            if flagged {
                let pos = node.start_position();
                violations.push(RuleViolation {
                    rule_id: "MSC09-C".to_string(),
                    severity: Severity::Low,
                    line: pos.row + 1,
                    column: pos.column + 1,
                    message: "string/character literal contains a non-ASCII byte (>= 0x80) -- not portable across locales/national ASCII variants".to_string(),
                    file_path: String::new(),
                    suggestion: Some(
                        "Restrict string and character literals to the portable ASCII subset (letters, digits, space, and basic punctuation)"
                            .to_string(),
                    ),
                    requires_manual_review: Some(false),
                });
                return;
            }
        }
    }

    fn traverse(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for kind in ["string_literal", "char_literal"] {
            for lit in query::find_descendants_of_kind(*root, kind) {
                self.check_literal(&lit, source, violations);
            }
        }
    }
}

impl CertRule for Msc09C {
    fn rule_id(&self) -> &'static str {
        "MSC09-C"
    }

    fn description(&self) -> &'static str {
        "Character encoding: Use subset of ASCII for safety"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "MSC09-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
