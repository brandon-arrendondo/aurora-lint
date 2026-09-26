// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{
    find_containing_function, get_node_text, resolve_field_expression_type,
    resolve_identifier_declarator,
};
use crate::utility::cert_c::float_typing::collect_variable_types;
use crate::utility::cert_c::overflow_helpers::resolve_typedef_chain;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use tree_sitter::Node;

#[derive(Default)]
pub struct Int02C {
    /// One-level typedef alias map from the prescan. Without it an operand
    /// spelled `u32`, `uint32`, `WORD` or any vendor integer alias classifies
    /// as unknown and is skipped -- which is most of the integer arithmetic in
    /// the embedded and CI-targeted code this rule is meant to run on.
    typedef_types: RefCell<Arc<HashMap<String, String>>>,
    /// The project map merged with the current file's own aliases, rebuilt per
    /// file. The injected map only arrives when a prescan ran (`-d`, or a
    /// header sweep); a typedef declared in the translation unit being scanned
    /// has to resolve either way.
    visible_typedefs: RefCell<HashMap<String, String>>,
    /// `struct tag -> {field -> type text}` from the prescan, so a field
    /// operand (`hdr->length`) can be resolved to the type it is declared
    /// with rather than skipped.
    struct_field_types: RefCell<Arc<HashMap<String, HashMap<String, String>>>>,
    /// The project's struct fields merged with this file's own, rebuilt per
    /// file for the same reason as `visible_typedefs`: a struct declared in
    /// the translation unit being scanned has to resolve whether or not a
    /// prescan supplied one.
    visible_struct_fields: RefCell<HashMap<String, HashMap<String, String>>>,
    /// Per-function `name -> type` maps, keyed by the function node's id.
    /// `resolve_field_expression_type` needs one, and rebuilding it for every
    /// field operand in a large function would be quadratic.
    function_type_maps: RefCell<HashMap<usize, HashMap<String, String>>>,
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

    fn set_project_context(&self, context: &ProjectContext) {
        *self.typedef_types.borrow_mut() = context.typedef_types.clone();
        *self.struct_field_types.borrow_mut() = context.struct_field_types.clone();
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
        self.rebuild_visible_typedefs(node, source);
        self.rebuild_visible_struct_fields(node, source);
        self.function_type_maps.borrow_mut().clear();

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
    /// Project aliases plus this file's own, so a typedef is resolvable
    /// whether or not a prescan supplied one.
    ///
    /// THIS FILE'S OWN DEFINITION WINS. The project map is keyed by NAME
    /// across the whole tree, and a name is not a type: two translation units
    /// may spell the same alias differently, and the one in scope here is the
    /// one this file declares. The project map is the fallback, for a name
    /// this file only receives through a header — headers are not expanded
    /// when a file is parsed, so the collector cannot see those.
    fn rebuild_visible_typedefs(&self, node: &Node, source: &str) {
        let mut merged: HashMap<String, String> = (**self.typedef_types.borrow()).clone();
        let mut file_local = HashMap::new();
        crate::analyze::prescan::collect_typedef_aliases(node, source, &mut file_local);
        merged.extend(file_local);
        *self.visible_typedefs.borrow_mut() = merged;
    }

    /// Project struct fields plus this file's own, this file's winning for the
    /// same reason as its typedefs — and here the reason is demonstrable. The
    /// prescan map is keyed by struct TAG across the whole tree, and a tag is
    /// not a type: curl defines two different `struct h3_stream_ctx`, one per
    /// QUIC backend, whose `id` field is `uint64_t` in one and `int64_t` in
    /// the other. With the project map winning, the ngtcp2 definition answered
    /// for the quiche file and produced a signed/unsigned comparison that is
    /// not in the code.
    fn rebuild_visible_struct_fields(&self, node: &Node, source: &str) {
        let mut merged: HashMap<String, HashMap<String, String>> =
            (**self.struct_field_types.borrow()).clone();
        let mut file_local = HashMap::new();
        crate::analyze::prescan::collect_struct_definitions(node, source, &mut file_local);
        merged.extend(file_local);
        *self.visible_struct_fields.borrow_mut() = merged;
    }

    fn operand_int_type(&self, node: &Option<Node>, source: &str) -> Option<IntType> {
        let mut node = (*node)?;
        while node.kind() == "parenthesized_expression" {
            node = node.named_child(0)?;
        }
        match node.kind() {
            "identifier" => self.declared_int_type(&node, get_node_text(&node, source), source),
            "field_expression" => self.field_int_type(&node, source),
            "subscript_expression" => self.element_int_type(&node, source),
            "call_expression" => self.call_result_int_type(&node, source),
            // `sizeof x` is size_t by definition, whatever x is.
            "sizeof_expression" => classify("size_t"),
            // A cast states the conversion, which is what INT02-C asks for.
            // A literal, a compound expression or anything else is not a type
            // this rule can name, and guessing is what produced its previous
            // false-positive population.
            _ => None,
        }
    }

    /// `hdr->length` — the type the struct field is declared with.
    fn field_int_type(&self, node: &Node, source: &str) -> Option<IntType> {
        let func = find_containing_function(node)?;
        let key = func.id();
        if !self.function_type_maps.borrow().contains_key(&key) {
            let map = collect_variable_types(&func, source);
            self.function_type_maps.borrow_mut().insert(key, map);
        }
        let maps = self.function_type_maps.borrow();
        let type_map = maps.get(&key)?;
        let text = resolve_field_expression_type(
            node,
            source,
            type_map,
            &self.visible_struct_fields.borrow(),
        )?;
        self.classify_spelling(&text)
    }

    /// `buf[i]` — the element type of the array or pointer being indexed,
    /// which is the declaration's base type once the subscript is applied.
    fn element_int_type(&self, node: &Node, source: &str) -> Option<IntType> {
        let base = node.child_by_field_name("argument")?;
        if base.kind() != "identifier" {
            return None;
        }
        let name = get_node_text(&base, source);
        let (decl, declarator) = resolve_identifier_declarator(&base, name, source)?;
        if !matches!(declarator.kind(), "array_declarator" | "pointer_declarator") {
            return None;
        }
        self.classify_spelling(&base_type_text(&decl, source)?)
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
                classify("size_t")
            }
            _ => None,
        }
    }

    /// The integer type the name is DECLARED with at this occurrence. `None`
    /// for a pointer, an array, a function, a struct, or a spelling that is
    /// not an integer even after typedefs are followed.
    fn declared_int_type(&self, ident: &Node, name: &str, source: &str) -> Option<IntType> {
        let (decl, declarator) = resolve_identifier_declarator(ident, name, source)?;
        if declarator.kind() != "identifier" {
            return None;
        }
        self.classify_spelling(&base_type_text(&decl, source)?)
    }

    /// Classify a type spelling, following typedefs when the spelling is not
    /// itself a standard one. The chain is walked to its terminal name and
    /// that is classified, so `u32 -> unsigned int` and a two-hop
    /// `paddr_t -> word_t -> unsigned long` both resolve.
    fn classify_spelling(&self, base: &str) -> Option<IntType> {
        if let Some(int_type) = classify(base) {
            return Some(int_type);
        }
        let terminal = resolve_typedef_chain(base, &self.visible_typedefs.borrow());
        if terminal == base {
            return None;
        }
        classify(&terminal)
    }
}

/// The type-specifier tokens of a `declaration`/`parameter_declaration` with
/// qualifiers and storage class dropped (`static const unsigned int x` ->
/// `"unsigned int"`). `None` for a struct/union/enum specifier, which is not
/// an integer.
fn base_type_text(decl: &Node, source: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for i in 0..decl.child_count() {
        let Some(child) = decl.child(i) else {
            continue;
        };
        match child.kind() {
            "primitive_type" | "sized_type_specifier" | "type_identifier" => {
                parts.extend(get_node_text(&child, source).split_whitespace());
            }
            "struct_specifier" | "union_specifier" | "enum_specifier" => return None,
            _ => {}
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

/// Classify a bare type spelling. Exhaustive by design: an unrecognised
/// spelling -- a typedef this rule cannot see through, `_Bool`, an enum --
/// yields `None` and is never reported, because both shapes need to know the
/// operand's rank and no text heuristic can supply it.
///
/// Plain `char` is deliberately absent. Its signedness is
/// implementation-defined, so neither shape can say what conversion happens,
/// and INT16-C leaves it out for the same reason.
fn classify(base: &str) -> Option<IntType> {
    use Rank::*;
    use Sign::*;
    let (sign, rank) = match base {
        "signed char" | "int8_t" => (Signed, Byte),
        "short" | "short int" | "signed short" | "signed short int" | "int16_t" => (Signed, Short),
        "int" | "signed" | "signed int" | "int32_t" => (Signed, Int),
        "long" | "long int" | "signed long" | "signed long int" => (Signed, Long),
        "long long" | "long long int" | "signed long long" | "signed long long int" | "int64_t" => {
            (Signed, LongLong)
        }

        "unsigned char" | "uint8_t" => (Unsigned, Byte),
        "unsigned short" | "unsigned short int" | "uint16_t" => (Unsigned, Short),
        "unsigned" | "unsigned int" | "uint32_t" => (Unsigned, Int),
        "unsigned long" | "unsigned long int" | "size_t" => (Unsigned, Long),
        "unsigned long long" | "unsigned long long int" | "uint64_t" | "uintmax_t" => {
            (Unsigned, LongLong)
        }

        _ => return None,
    };
    Some(IntType { sign, rank })
}
