// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! MSC10-C: Character encoding: UTF8-related issues
//!
//! UTF-8 is a variable-width encoding, and the same code point can be spelled
//! by more than one byte sequence unless a decoder insists on the *shortest*
//! form. A decoder that validates only the structural shape of a sequence
//! (lead byte followed by the right number of `10xxxxxx` continuation bytes)
//! but never rejects non-shortest ("overlong") encodings will accept `C0 80`
//! as U+0000 and `2F C0 AE 2E 2F` as `/../`, letting input survive a
//! security check in one spelling and be interpreted as something else after
//! decoding. This is the CWE-176 / CWE-116 attack the wiki's prose warns
//! about.
//!
//! The wiki gives no noncompliant/compliant pair, but it does publish a
//! reference validator (`spc_utf8_isvalid()`) together with the explicit
//! caveat that it "does not reject non-minimal forms". That is the concrete,
//! statically checkable shape this rule targets: a hand-rolled UTF-8
//! decoder/validator that performs the lead-byte/continuation-byte mask
//! cascade but contains none of the constants an overlong-rejection check
//! would need.
//!
//! Recognition is deliberately narrow to keep this off ordinary byte-level
//! parsing code. A function must both:
//!   1. compare at least three *distinct* UTF-8 lead-byte masks
//!      (`0xc0`/`0xe0`/`0xf0`/`0xf8`/`0xfc`) against a constant, and
//!   2. involve `0x80` (the ASCII/continuation-byte test every UTF-8
//!      decoder performs).
//!
//! A function that clears that bar is then checked for any marker of a
//! shortest-form check -- a code-point minimum (`0x800`, `0x10000`), an
//! overlong lead-byte rejection (`0xc0`/`0xc1` as a compared value), the
//! `0xa0`/`0x90` second-byte floors for the `E0`/`F0` lead bytes, a
//! surrogate-range check, or a comment naming the concept. The check is
//! intentionally generous: a missed marker yields a false negative, not a
//! false positive on a decoder that is in fact correct.
//!
//! CERT C reference:
//! https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/recommendations/miscellaneous-msc/msc10-c

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg;
use crate::analyze::const_eval::{self, MacroConstantMap};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

/// The "top N bits set" masks a UTF-8 decoder tests a lead byte against.
/// `0x80` is deliberately excluded -- it is far too common in unrelated
/// byte-level code to count toward recognizing a decoder on its own.
const UTF8_LEAD_MASKS: [i64; 5] = [0xc0, 0xe0, 0xf0, 0xf8, 0xfc];

/// Minimum number of distinct [`UTF8_LEAD_MASKS`] entries a function must
/// test before it is treated as a hand-rolled UTF-8 decoder.
const MIN_DISTINCT_LEAD_MASKS: usize = 3;

/// Constants that only appear in code doing a shortest-form/range check:
/// the 2- and 3-byte code-point minimums, the Unicode maximum, the always
/// overlong `0xc0`/`0xc1` lead bytes, the `0xa0`/`0x90` second-byte floors
/// that constrain the `E0`/`F0` lead bytes, and the surrogate range.
const OVERLONG_CHECK_CONSTANTS: [i64; 9] = [
    0x800,    // smallest code point legally encoded in 3 bytes
    0x10000,  // smallest code point legally encoded in 4 bytes
    0x110000, // one past the largest valid code point
    0xc1,     // C0/C1 are always overlong lead bytes
    0xa0,     // E0 requires a second byte >= A0
    0x90,     // F0 requires a second byte >= 90
    0xd800,   // low surrogate boundary
    0xdfff,   // high surrogate boundary
    0xffff,   // BMP boundary, often paired with a 4-byte minimum check
];

/// Words a developer writes when they are handling the shortest-form rule.
const OVERLONG_CHECK_WORDS: [&str; 6] = [
    "overlong",
    "shortest",
    "non-minimal",
    "nonminimal",
    "minimal form",
    "canonical",
];

#[derive(Debug)]
pub struct Msc10C;

impl Msc10C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Msc10C
    }

    /// Collect every integer constant appearing anywhere in `body`, plus the
    /// subset of those used as the constant side of a bitwise-`&` mask.
    ///
    /// Both sets are macro-aware (via `macros`), so a decoder written against
    /// `#define UTF8_CONT_MASK 0xc0` is recognized the same as a literal one.
    fn collect_constants(
        &self,
        body: &Node,
        source: &str,
        macros: &MacroConstantMap,
    ) -> (HashSet<i64>, HashSet<i64>) {
        let mut all_constants: HashSet<i64> = HashSet::new();
        let mut mask_constants: HashSet<i64> = HashSet::new();

        for expr in query::find_descendants_of_kind(*body, "binary_expression") {
            let (Some(left), Some(right)) = (
                expr.child_by_field_name("left"),
                expr.child_by_field_name("right"),
            ) else {
                continue;
            };
            let left_val =
                const_eval::try_evaluate_text_public(get_node_text(&left, source), macros);
            let right_val =
                const_eval::try_evaluate_text_public(get_node_text(&right, source), macros);

            // The `&` in `(*c & 0xe0) == 0xc0` -- whichever side folds to a
            // constant is the mask.
            if self.operator_is_bitand(&expr, source) {
                for val in [left_val, right_val].into_iter().flatten() {
                    mask_constants.insert(val);
                }
            }
            for val in [left_val, right_val].into_iter().flatten() {
                all_constants.insert(val);
            }
        }

        // Catch constants outside any binary expression (e.g. a `switch` label
        // or an initializer) so the overlong-marker scan sees them too.
        for lit in query::find_descendants_of_kind(*body, "number_literal") {
            if let Some(val) =
                const_eval::try_evaluate_text_public(get_node_text(&lit, source), macros)
            {
                all_constants.insert(val);
            }
        }

        (all_constants, mask_constants)
    }

    /// True if `expr`'s operator token is a single `&` (not `&&`).
    fn operator_is_bitand(&self, expr: &Node, source: &str) -> bool {
        for i in 0..expr.child_count() {
            if let Some(child) = expr.child(i) {
                if !child.is_named() && get_node_text(&child, source).trim() == "&" {
                    return true;
                }
            }
        }
        false
    }

    /// True if this function performs the UTF-8 lead-byte mask cascade that
    /// identifies a hand-rolled decoder/validator.
    fn looks_like_utf8_decoder(
        &self,
        all_constants: &HashSet<i64>,
        mask_constants: &HashSet<i64>,
    ) -> bool {
        let distinct_lead_masks = UTF8_LEAD_MASKS
            .iter()
            .filter(|m| mask_constants.contains(m))
            .count();
        distinct_lead_masks >= MIN_DISTINCT_LEAD_MASKS && all_constants.contains(&0x80)
    }

    /// True if the function shows any sign of rejecting non-shortest forms.
    fn has_overlong_rejection(&self, all_constants: &HashSet<i64>, body_text: &str) -> bool {
        if OVERLONG_CHECK_CONSTANTS
            .iter()
            .any(|c| all_constants.contains(c))
        {
            return true;
        }
        let lowered = body_text.to_lowercase();
        OVERLONG_CHECK_WORDS.iter().any(|w| lowered.contains(w))
    }
}

impl CertRule for Msc10C {
    fn rule_id(&self) -> &'static str {
        "MSC10-C"
    }

    fn description(&self) -> &'static str {
        "Character encoding: UTF8-related issues"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "MSC10-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let macros = const_eval::collect_macro_constants(root, source);

        for func in query::find_descendants_of_kind(*root, "function_definition") {
            let Some(body) = func.child_by_field_name("body") else {
                continue;
            };
            let (all_constants, mask_constants) = self.collect_constants(&body, source, &macros);
            if !self.looks_like_utf8_decoder(&all_constants, &mask_constants) {
                continue;
            }
            if self.has_overlong_rejection(&all_constants, get_node_text(&func, source)) {
                continue;
            }

            let name = cfg::get_function_name(&func, source).unwrap_or("<anonymous>");
            let pos = func.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::Medium,
                message: format!(
                    "'{}' validates UTF-8 sequence structure but never rejects non-shortest (overlong) encodings -- 'C0 80' would be accepted as U+0000",
                    name
                ),
                file_path: String::new(),
                line: pos.row + 1,
                column: pos.column + 1,
                suggestion: Some(
                    "Reject non-shortest forms: verify the decoded code point meets the minimum for its byte length (>= 0x80 for 2 bytes, >= 0x800 for 3, >= 0x10000 for 4), or use a vetted UTF-8 decoder"
                        .to_string(),
                ),
                requires_manual_review: Some(false),
            });
        }
    }
}
