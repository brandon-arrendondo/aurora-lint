// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::VisibleTypes;
use crate::manifest::Severity;
use crate::settings::{AnalysisSettings, DataModel};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::expr_type::{self, CType, Rank, TypeEnv};
use lang_parsing_substrate::query;
use std::cell::{Cell, RefCell};
use tree_sitter::Node;

#[derive(Default)]
pub struct Int02C {
    /// The typedefs and struct fields this file sees (the project's, this
    /// file's own definitions winning), so an operand spelled `u32`, `WORD`
    /// or any vendor integer alias, or a field operand (`hdr->length`), is
    /// typed by its declaration rather than skipped. A name is not a type:
    /// curl defines two different `struct h3_stream_ctx`, one per QUIC
    /// backend, whose `id` is `uint64_t` in one and `int64_t` in the other,
    /// and the one in scope is the file's own.
    visible: RefCell<VisibleTypes>,
    /// The integer data model the settings credit, for typing.
    data_model: Cell<DataModel>,
}

/// An operand's integer type as this rule reasons about it: its sign, its
/// rank when the data model fixes it, and its width in bits (at least
/// `min_bits`; exactly `max_bits` when that is known). Under the default
/// model, ISO C's, only the guaranteed minimum widths are known, so a
/// question such as "does it promote to int?" can have the answer "on some
/// implementations".
#[derive(Clone, Copy)]
struct IntType {
    signed: bool,
    rank: Option<Rank>,
    max_bits: Option<u32>,
}

impl IntType {
    /// Whether the integer promotions may make this a signed `int`: it is
    /// below `int` and `int` holds its values on some implementation the
    /// model allows. A signed type below `int` always promotes to it.
    fn may_promote_to_int(&self, model: DataModel) -> bool {
        match self.rank {
            Some(r) if r >= Rank::Int => false,
            Some(_) if self.signed => true,
            // Unsigned below int: to int only where int is wider.
            _ => match (self.max_bits, model.exact_width(Rank::Int)) {
                (Some(w), Some(int)) => w < int,
                _ => true,
            },
        }
    }

    /// Whether this may still be unsigned after the promotions: `unsigned
    /// int` or wider, or a narrower unsigned type as wide as `int` on some
    /// implementation the model allows (an `unsigned short` where `short` and
    /// `int` are both 16 bits).
    fn may_stay_unsigned(&self, model: DataModel) -> bool {
        !self.signed
            && match self.rank {
                Some(r) if r >= Rank::Int => true,
                _ => match (self.max_bits, model.exact_width(Rank::Int)) {
                    (Some(w), Some(int)) => w >= int,
                    _ => true,
                },
            }
    }

    /// Its rank and exact width once promoted, when the model fixes both.
    fn promoted(&self, model: DataModel) -> Option<(Rank, u32)> {
        match self.rank? {
            r if r < Rank::Int => Some((Rank::Int, model.exact_width(Rank::Int)?)),
            r => Some((r, self.max_bits?)),
        }
    }

    /// Its largest value, when its width is known.
    fn max_value(&self) -> Option<u128> {
        let w = self.max_bits?;
        Some(if self.signed {
            (1u128 << (w - 1)) - 1
        } else {
            (1u128 << w) - 1
        })
    }
}

impl CertRule for Int02C {
    fn rule_id(&self) -> &'static str {
        "INT02-C"
    }
    fn description(&self) -> &'static str {
        "Understand integer conversion rules"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cert_id(&self) -> &'static str {
        "INT02-C"
    }

    fn set_visible_types(&self, types: &VisibleTypes) {
        *self.visible.borrow_mut() = types.clone();
    }

    fn set_analysis_settings(&self, settings: &std::sync::Arc<AnalysisSettings>) {
        self.data_model.set(settings.data_model);
    }

    // Every question here is answered from the type the operand's own
    // declaration gives it, resolved at that occurrence
    // (`resolve_identifier_declarator`: nearest enclosing block, else the
    // containing function's parameters, else file scope).
    //
    // The previous implementation asked none of that. Its whole output came
    // from one branch that tested whether the node's TEXT contained a `*`
    // and whether the literal string "unsigned short" appeared anywhere
    // earlier in the FILE -- so a pointer dereference below an unrelated
    // declaration was reported as an unsigned-short multiplication. Two
    // further branches keyed on the identifier names `si`/`ui` and `char i`
    // /`unsigned char max`, the variable names from the CERT wiki examples,
    // and so could only fire on code that copied them: renaming them in the
    // rule's own fixture made the identical defect invisible. All 431
    // real-world findings ever adjudicated against that version were false.
    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for expr in query::find_descendants_of_kind(*node, "binary_expression") {
            let Some(op) = expr.child_by_field_name("operator") else {
                continue;
            };
            match get_node_text(&op, source) {
                "*" => self.check_narrow_multiplication(&expr, source, violations),
                "<" | ">" | "<=" | ">=" | "==" | "!=" => {
                    self.check_mixed_sign_comparison(&expr, source, violations)
                }
                _ => {}
            }
        }
    }
}

impl Int02C {
    /// `unsigned short x = 45000, y = 50000; ... x * y`
    ///
    /// Both operands promote to `int`, so the product is computed in `int`
    /// and can overflow it -- undefined behaviour, and it happens in the
    /// multiplication itself. Where the result is stored, or whether it is
    /// stored at all, is therefore irrelevant: an earlier version of this
    /// check required an `int`-ranked-or-wider destination and so missed
    /// `unsigned short z = x * y` and `if (x * y > n)`, both equally
    /// undefined.
    ///
    /// Whether the product can exceed `INT_MAX` depends on the widths. On a
    /// declared LP64 target only two 16-bit unsigned operands can (65535 *
    /// 65535); two 8-bit ones reach 65025, inside a 32-bit `int`. ISO C
    /// guarantees `int` only 16 bits, where 255 * 255 already overflows, and
    /// lets `int` be wider than `uint32_t`, so under the default model any two
    /// operands that may promote to `int` are reported unless their exact
    /// widths keep the product inside the smallest `int` they could promote
    /// to (two `int8_t`s: 127 * 127 fits 16 bits).
    fn check_narrow_multiplication(
        &self,
        expr: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let model = self.data_model.get();
        let (Some(left), Some(right)) = (
            self.operand_int_type(&expr.child_by_field_name("left"), source),
            self.operand_int_type(&expr.child_by_field_name("right"), source),
        ) else {
            return;
        };
        // The defect is an UNSIGNED product computed in a signed int. A signed
        // operand's overflow is INT32-C's, reported on the same line already.
        if left.signed || right.signed {
            return;
        }
        if !(left.may_promote_to_int(model) && right.may_promote_to_int(model)) {
            return;
        }
        // The narrowest int both could promote to: wide enough to hold each
        // operand's values.
        let int_bits = model.exact_width(Rank::Int).unwrap_or_else(|| {
            [left, right]
                .iter()
                .filter_map(|t| t.max_bits.map(|w| if t.signed { w } else { w + 1 }))
                .fold(model.min_width(Rank::Int), u32::max)
        });
        let int_max = (1u128 << (int_bits - 1)) - 1;
        if let (Some(a), Some(b)) = (left.max_value(), right.max_value()) {
            if a * b <= int_max {
                return;
            }
        }

        let message = if model.exact_width(Rank::Int).is_some() {
            "Multiplication of two 16-bit unsigned operands is performed in int \
             after promotion, where the product can exceed INT_MAX and overflow"
        } else {
            "Multiplication of two operands that promote to int wherever int is \
             wider than they are: ISO C guarantees int only 16 bits, so the \
             product can exceed INT_MAX and overflow"
        };
        violations.push(self.violation(
            expr,
            message.to_string(),
            "Cast one operand to unsigned int before multiplying",
        ));
    }

    /// `int si; unsigned int ui; si < ui`
    ///
    /// The signed operand converts to unsigned, so a negative value compares
    /// as a very large one. It keeps its sign only when, after the integer
    /// promotions, its type outranks the unsigned one AND is wider (C11
    /// 6.3.1.8): a `long` against an `unsigned int` on LP64. Where the
    /// unsigned operand promotes to `int` (`char i < unsigned char max` on
    /// most targets), the comparison is signed-vs-signed and this is not the
    /// defect.
    ///
    /// Under the default model no width beyond ISO C's minimums is known, so
    /// neither exception is proven: an `unsigned char` is as wide as `int`
    /// where `CHAR_BIT` is 16, and `long` is no wider than `unsigned int` on
    /// LLP64. Such a comparison is reported with a message saying so.
    fn check_mixed_sign_comparison(
        &self,
        expr: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let model = self.data_model.get();
        let (Some(left), Some(right)) = (
            self.operand_int_type(&expr.child_by_field_name("left"), source),
            self.operand_int_type(&expr.child_by_field_name("right"), source),
        ) else {
            return;
        };

        let (signed, unsigned) = match (left.signed, right.signed) {
            (true, false) => (left, right),
            (false, true) => (right, left),
            _ => return,
        };
        if !unsigned.may_stay_unsigned(model) {
            return;
        }
        if let (Some((sr, sw)), Some((ur, uw))) = (signed.promoted(model), unsigned.promoted(model))
        {
            if sr > ur && sw > uw {
                return;
            }
        }

        let message = if model.exact_width(Rank::Int).is_some() {
            "Comparison between a signed and an unsigned integer of the same \
             or greater rank: the signed operand is converted to unsigned, so \
             a negative value compares as a large positive one"
        } else {
            "Comparison between a signed and an unsigned integer where ISO C does \
             not guarantee the signed type is the wider: on some conforming \
             implementations the signed operand is converted to unsigned, so a \
             negative value compares as a large positive one"
        };
        violations.push(self.violation(
            expr,
            message.to_string(),
            "Cast explicitly, or check the signed operand for a negative value first",
        ));
    }

    fn violation(&self, node: &Node, message: String, suggestion: &str) -> RuleViolation {
        RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            file_path: String::new(),
            message,
            suggestion: Some(suggestion.to_string()),
            requires_manual_review: None,
        }
    }
}

/// The integer type of an operand, or `None` when the rule cannot be sure.
///
/// A `cast_expression` yields `None` on purpose: the conversion is written
/// down, which is precisely what INT02-C asks for, so neither shape should
/// report it. A literal, a call and a field access likewise yield `None` --
/// the operand's type is not in reach here, and guessing is what produced
/// this rule's previous false-positive population.
impl Int02C {
    fn operand_int_type(&self, node: &Option<Node>, source: &str) -> Option<IntType> {
        let mut node = (*node)?;
        while node.kind() == "parenthesized_expression" {
            node = node.named_child(0)?;
        }
        let visible = self.visible.borrow();
        let env = TypeEnv::visible(&visible, self.data_model.get());
        let declared = match node.kind() {
            // The type the name, the struct field, or the indexed array's
            // element is declared with, at this occurrence.
            "identifier" | "field_expression" | "subscript_expression" => {
                expr_type::expr_type(&node, source, &env)
            }
            "call_expression" => return self.call_result_int_type(&node, source),
            // `sizeof x` is size_t by definition, whatever x is.
            "sizeof_expression" => expr_type::expr_type(&node, source, &env),
            // A cast states the conversion, which is what INT02-C asks for.
            // A literal, a compound expression or anything else is not a type
            // this rule can name, and guessing is what produced its previous
            // false-positive population.
            _ => None,
        };
        int_type(declared?, self.data_model.get())
    }

    /// The return type of a standard library function whose result type is
    /// fixed by the standard. Only the size_t-returning ones are listed: they
    /// are the ones that produce the classic `int i < strlen(s)` comparison.
    /// A project-defined function is not guessed at.
    fn call_result_int_type(&self, node: &Node, source: &str) -> Option<IntType> {
        let function = node.child_by_field_name("function")?;
        if function.kind() != "identifier" {
            return None;
        }
        match get_node_text(&function, source) {
            "strlen" | "strnlen" | "wcslen" | "strspn" | "strcspn" | "fread" | "fwrite" => {
                let model = self.data_model.get();
                int_type(expr_type::standard_alias(model, "size_t")?, model)
            }
            _ => None,
        }
    }
}

/// The rule's view of a declared type: an integer with a known sign. `None`
/// for a pointer, an array, a function, a struct, a float, `_Bool`, and plain
/// `char`, whose signedness is implementation-defined, so neither shape can
/// say what conversion happens (INT16-C leaves it out for the same reason).
/// An unknown type is never reported, and no text heuristic can supply one.
fn int_type(t: CType, model: DataModel) -> Option<IntType> {
    let (sign, rank, max_bits) = match t {
        CType::Int { sign, rank } => (sign, Some(rank), model.exact_width(rank)),
        CType::IntOfWidth { sign, max_bits, .. } => (sign, None, max_bits),
        _ => return None,
    };
    if rank == Some(Rank::Bool) {
        return None;
    }
    let signed = match sign {
        expr_type::Sign::Signed => true,
        expr_type::Sign::Unsigned => false,
        expr_type::Sign::PlainChar => return None,
    };
    Some(IntType {
        signed,
        rank,
        max_bits,
    })
}
