// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! FLP00-C: Understand the limitations of floating-point numbers
//!
//! Floating-point numbers have finite precision and are prone to rounding errors.
//! Different platforms (IEEE 754 vs IBM) and compiler optimization levels can
//! produce different results for the same floating-point operations. Direct
//! equality comparisons of floating-point values should be avoided.
//!
//! The rule reports an `==` or `!=` with an operand of floating type, the type
//! decided by the operand's resolved declaration (a variable, a typedef of
//! `double`, a struct member, a `<math.h>` call, a floating literal), not by
//! its spelling. A comparison with an exact zero (`x == 0.0`, `d != 0`) is a
//! common, legitimate test: the default policy does not report it, by the
//! option `flp00_exact_zero_comparison_exempt`; the strict policy reports it
//! as any other comparison (ADR-0015 Decision 7).
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! float c = a / b;
//! if (c == a / b) {  // Direct equality comparison
//!     // May fail unpredictably
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! float c = a / b;
//! float diff = fabsf(c - (a / b));
//! if (diff <= __FLT_EPSILON__) {  // Epsilon-based comparison
//!     // Robust comparison
//! }
//! ```
//!
//! **Compliant (using relative difference):**
//! ```c
//! float RelDif(float a, float b) {
//!   float c = fabsf(a);
//!   float d = fabsf(b);
//!   d = fmaxf(c, d);
//!   return d == 0.0f ? 0.0f : fabsf(a - b) / d;
//! }
//!
//! if (RelDif(c, a / b) <= __FLT_EPSILON__) {
//!     // Comparison succeeds
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::VisibleTypes;
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::expr_type::{self, TypeEnv};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::sync::Arc;
use tree_sitter::Node;

/// The option that exempts a comparison with an exact zero.
const EXACT_ZERO_OPTION: &str = "flp00_exact_zero_comparison_exempt";

#[derive(Default)]
pub struct Flp00C {
    /// The typedefs and struct fields this file sees, so an operand declared
    /// `real` (a typedef of double) or `p->ratio` is typed by its declaration.
    visible: RefCell<VisibleTypes>,
    /// The settings: the data model for typing, and the exact-zero option.
    settings: RefCell<Arc<AnalysisSettings>>,
}

impl CertRule for Flp00C {
    fn rule_id(&self) -> &'static str {
        "FLP00-C"
    }

    fn description(&self) -> &'static str {
        "Understand the limitations of floating-point numbers"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "FLP00-C"
    }

    fn set_visible_types(&self, types: &VisibleTypes) {
        *self.visible.borrow_mut() = types.clone();
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        *self.settings.borrow_mut() = Arc::clone(settings);
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        let settings = self.settings.borrow();
        let visible = self.visible.borrow();
        let env = TypeEnv::visible(&visible, settings.facts).in_tree(*root);
        let zero_exempt = settings.flag(EXACT_ZERO_OPTION);
        let mut violations = Vec::new();
        self.find_fp_equality_comparisons(root, source, &env, zero_exempt, &mut violations);
        violations
    }
}

impl Flp00C {
    /// Find direct equality comparisons of floating-point values
    fn find_fp_equality_comparisons(
        &self,
        node: &Node,
        source: &str,
        env: &TypeEnv,
        zero_exempt: bool,
        violations: &mut Vec<RuleViolation>,
    ) {
        for node in query::find_descendants_of_kind(*node, "binary_expression") {
            let Some(operator) = node.child_by_field_name("operator") else {
                continue;
            };
            let op_text = get_node_text(&operator, source);
            if op_text != "==" && op_text != "!=" {
                continue;
            }
            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                continue;
            };
            // Either operand floating makes the comparison a floating one:
            // the usual arithmetic conversions convert the other to its type.
            let is_float =
                |n: &Node| expr_type::expr_type(n, source, env).is_some_and(|t| t.is_float());
            if !is_float(&left) && !is_float(&right) {
                continue;
            }
            if zero_exempt && (is_exact_zero(&left, source) || is_exact_zero(&right, source)) {
                continue;
            }
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                message: format!(
                    "Direct {} comparison of floating-point values. \
                     Floating-point arithmetic has finite precision and may produce \
                     unexpected results across platforms and optimization levels.",
                    if op_text == "==" {
                        "equality"
                    } else {
                        "inequality"
                    }
                ),
                severity: self.severity(),
                line: operator.start_position().row + 1,
                column: operator.start_position().column + 1,
                file_path: String::new(),
                suggestion: Some(
                    "Use epsilon-based comparison (e.g., fabsf(a - b) <= __FLT_EPSILON__) \
                     or a relative difference function for robust floating-point comparisons"
                        .to_string(),
                ),
                requires_manual_review: Some(true),
            });
        }
    }
}

/// Whether `node` is a constant whose value is exactly zero: a floating or
/// integer literal (`0.0`, `0.f`, `.0`, `0e5`, `0`, `0x0`) or the null
/// character constant (`'\0'`), parenthesized or signed (`-0.0`).
fn is_exact_zero(node: &Node, source: &str) -> bool {
    match node.kind() {
        "parenthesized_expression" => node
            .named_child(0)
            .is_some_and(|n| is_exact_zero(&n, source)),
        "unary_expression" => {
            let op = node
                .child_by_field_name("operator")
                .map(|o| get_node_text(&o, source));
            matches!(op, Some("-" | "+"))
                && node
                    .child_by_field_name("argument")
                    .is_some_and(|n| is_exact_zero(&n, source))
        }
        "number_literal" => literal_is_zero(get_node_text(node, source)),
        "char_literal" => char_literal_is_zero(get_node_text(node, source)),
        _ => false,
    }
}

/// Whether a character constant's value is zero: an octal or hexadecimal
/// escape whose digits are all zero (`'\0'`, `'\000'`, `L'\x0'`), C11
/// 6.4.4.4. The prefix (`L`, `u`, `U`, `u8`) does not change the value.
fn char_literal_is_zero(text: &str) -> bool {
    let Some(body) = text
        .split_once('\'')
        .and_then(|(_, rest)| rest.strip_suffix('\''))
    else {
        return false;
    };
    let digits = match body.strip_prefix('\\') {
        Some(escape) => escape.strip_prefix(['x', 'X']).unwrap_or(escape),
        None => return false,
    };
    !digits.is_empty() && digits.chars().all(|c| c == '0')
}

/// Whether a numeric literal's spelling denotes zero (C11 6.4.4.1,
/// 6.4.4.2). tree-sitter's `number_literal` token also takes a leading sign
/// (`-0.0`), a binary prefix and the C23 suffixes.
fn literal_is_zero(text: &str) -> bool {
    let text = text.replace('\'', "").to_ascii_lowercase();
    let text = text.trim_start_matches(['-', '+']);
    if let Some(hex) = text.strip_prefix("0x") {
        // A hexadecimal constant is zero when every digit of its significand
        // is, whatever its exponent (`0x0p3`). Only `u` and `l` are trimmed:
        // `b`, `d` and `f` are hexadecimal digits.
        let significand = hex.split('p').next().unwrap_or("");
        let significand = significand.trim_end_matches(['u', 'l']);
        return significand.contains('0') && significand.chars().all(|c| c == '0' || c == '.');
    }
    let digits = text.strip_prefix("0b").unwrap_or(text);
    // A decimal or binary constant: drop an integer or floating suffix, then
    // the value is zero when every digit before the exponent is.
    let mantissa = digits.split('e').next().unwrap_or("");
    let mantissa = mantissa.trim_end_matches(['u', 'l', 'w', 'b', 'f', 'd']);
    mantissa.contains('0') && mantissa.chars().all(|c| c == '0' || c == '.')
}
