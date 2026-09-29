// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::VisibleTypes;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::expr_type::{self, CType, TypeEnv};
use lang_parsing_substrate::query;
use std::cell::RefCell;
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
}

/// Integer conversion rank, coarse enough for the only two questions this
/// rule asks: does an operand promote to `int` before the operation happens
/// (`Narrow` does), and which of two operands wins the usual arithmetic
/// conversions.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Rank {
    /// 8-bit. Below `int`, so promoted to `int` before any arithmetic.
    Byte,
    /// 16-bit. Below `int`, so promoted to `int` before any arithmetic.
    Short,
    Int,
    Long,
    LongLong,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sign {
    Signed,
    Unsigned,
}

#[derive(Clone, Copy)]
struct IntType {
    sign: Sign,
    rank: Rank,
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
    /// Only 16-bit operands qualify. Two 8-bit values reach at most
    /// 255 * 255 = 65025, comfortably inside `int`, so `unsigned char`
    /// operands are excluded rather than reported. Signed operands are
    /// excluded for the same arithmetic reason: 32767 * 32767 also fits.
    fn check_narrow_multiplication(
        &self,
        expr: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let (Some(left), Some(right)) = (
            self.operand_int_type(&expr.child_by_field_name("left"), source),
            self.operand_int_type(&expr.child_by_field_name("right"), source),
        ) else {
            return;
        };

        if left.sign != Sign::Unsigned || right.sign != Sign::Unsigned {
            return;
        }
        if left.rank != Rank::Short || right.rank != Rank::Short {
            return;
        }

        violations.push(
            self.violation(
                expr,
                "Multiplication of two 16-bit unsigned operands is performed in int \
             after promotion, where the product can exceed INT_MAX and overflow"
                    .to_string(),
                "Cast one operand to unsigned int before multiplying",
            ),
        );
    }

    /// `int si; unsigned int ui; si < ui`
    ///
    /// The signed operand converts to unsigned, so a negative value compares
    /// as a very large one. Only reported when BOTH operands are `int`-ranked
    /// or wider: anything narrower promotes to `int` first and the comparison
    /// is then signed-vs-signed, which is why `char i < unsigned char max` is
    /// NOT this defect. The unsigned operand must also be at least as wide as
    /// the signed one -- where the signed type is wider it is the unsigned
    /// operand that converts, value-preserving.
    fn check_mixed_sign_comparison(
        &self,
        expr: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let (Some(left), Some(right)) = (
            self.operand_int_type(&expr.child_by_field_name("left"), source),
            self.operand_int_type(&expr.child_by_field_name("right"), source),
        ) else {
            return;
        };

        let (signed, unsigned) = match (left.sign, right.sign) {
            (Sign::Signed, Sign::Unsigned) => (left, right),
            (Sign::Unsigned, Sign::Signed) => (right, left),
            _ => return,
        };

        if signed.rank < Rank::Int || unsigned.rank < Rank::Int {
            return;
        }
        if unsigned.rank < signed.rank {
            return;
        }

        violations.push(
            self.violation(
                expr,
                "Comparison between a signed and an unsigned integer of the same \
             or greater rank: the signed operand is converted to unsigned, so \
             a negative value compares as a large positive one"
                    .to_string(),
                "Cast explicitly, or check the signed operand for a negative value first",
            ),
        );
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
        let env = TypeEnv::visible(&visible);
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
        int_type(declared?)
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
                Some(IntType {
                    sign: Sign::Unsigned,
                    rank: Rank::Long,
                })
            }
            _ => None,
        }
    }
}

/// The rule's view of a declared type: an integer with a known sign. `None`
/// for a pointer, an array, a function, a struct, a float, `_Bool`, and plain
/// `char`, whose signedness is implementation-defined, so neither shape can
/// say what conversion happens (INT16-C leaves it out for the same reason).
/// An unknown type is never reported: both shapes need the operand's rank,
/// and no text heuristic can supply it.
fn int_type(t: CType) -> Option<IntType> {
    let CType::Int { sign, rank } = t else {
        return None;
    };
    let sign = match sign {
        expr_type::Sign::Signed => Sign::Signed,
        expr_type::Sign::Unsigned => Sign::Unsigned,
        expr_type::Sign::PlainChar => return None,
    };
    let rank = match rank {
        expr_type::Rank::Bool => return None,
        expr_type::Rank::Char => Rank::Byte,
        expr_type::Rank::Short => Rank::Short,
        expr_type::Rank::Int => Rank::Int,
        expr_type::Rank::Long => Rank::Long,
        expr_type::Rank::LongLong => Rank::LongLong,
    };
    Some(IntType { sign, rank })
}
