// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! The C type of an expression, read from the declarations it names.
//!
//! A name is not a variable (ADR-0006). Every identifier is typed by the
//! declaration it resolves to at that occurrence
//! ([`ast_utils::resolve_identifier_declarator`]); a type specifier is read
//! as a set of tokens from the declaration's own specifier nodes, never by
//! searching text for a substring; a `type_identifier` is followed through
//! the typedef chain and then a fixed table of standard aliases. The answer
//! is `None` whenever the type is not in reach -- an identifier that resolves
//! to nothing in this file, a call, a typedef no prescan saw. `None` means
//! UNKNOWN: a caller must never treat it as "not float" or "not unsigned"
//! when that answer would silence a finding, and never as "float" or
//! "unsigned" when it would raise one.
//!
//! Widths and the standard aliases come from a [`DataModel`], so the integer
//! model of the target is a parameter rather than a constant. Only LP64 is
//! implemented; an LLP64 target (a Windows build) is typed as LP64 for now.
//!
//! Known losses, inherited from the prescan's `struct_field_types`: a field is
//! spelled with at most one ` *` whatever its pointer depth, and an array
//! field is spelled as its element type, so a field is typed no more precisely
//! than that spelling says.

use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::float_typing::EXTENDED_FLOAT_TYPES;
use crate::utility::cert_c::overflow_helpers::resolve_typedef_chain;
use std::collections::HashMap;
use tree_sitter::Node;

/// Signedness of an integer type. Plain `char` is its own case: whether it is
/// signed is implementation-defined, so it is never claimed as either.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sign {
    /// `signed char`, `short`, `int`, `long`, `long long` and their aliases.
    Signed,
    /// The `unsigned` forms, `_Bool`, and unsigned aliases such as `size_t`.
    Unsigned,
    /// Plain `char`.
    PlainChar,
}

/// Integer conversion rank (C11 6.3.1.1), `Bool` lowest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rank {
    /// `_Bool`.
    Bool,
    /// The three `char` types.
    Char,
    /// `short`.
    Short,
    /// `int`.
    Int,
    /// `long`.
    Long,
    /// `long long`.
    LongLong,
}

/// A real floating type, ordered by range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FloatKind {
    /// `float`.
    Float,
    /// `double`.
    Double,
    /// `long double`.
    LongDouble,
    /// `_FloatN`, `_DecimalN`, `__float128` and the like: floating-point, with
    /// no place in the float < double < long double order.
    Extended,
}

/// The type of an expression or a declared object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CType {
    /// An integer type, `_Bool` and the `char` types included.
    Int {
        /// Its signedness.
        sign: Sign,
        /// Its conversion rank.
        rank: Rank,
    },
    /// A real floating type.
    Float(FloatKind),
    /// A pointer; the pointee when it is known.
    Pointer(Option<Box<CType>>),
    /// An array; the element type when it is known.
    Array(Option<Box<CType>>),
    /// A struct or union, by the name its fields are filed under (the tag, or
    /// the typedef name of a typedef'd struct), when it has one.
    Record(Option<String>),
    /// An enumeration.
    Enum,
    /// `void`.
    Void,
    /// A function, which an identifier naming one designates; its return
    /// type when it is known.
    Function(Option<Box<CType>>),
}

impl CType {
    /// A real floating type.
    pub fn is_float(&self) -> bool {
        matches!(self, CType::Float(_))
    }

    /// An integer type (`_Bool` and the `char` types included, enumerations
    /// not).
    pub fn is_integer(&self) -> bool {
        matches!(self, CType::Int { .. })
    }

    /// A pointer (an array is not one until it decays).
    pub fn is_pointer(&self) -> bool {
        matches!(self, CType::Pointer(_))
    }

    /// Arithmetic: an integer (enumerations included) or a real float.
    pub fn is_arithmetic(&self) -> bool {
        matches!(self, CType::Int { .. } | CType::Float(_) | CType::Enum)
    }

    /// `Some(true)` for an unsigned integer, `Some(false)` for a signed one,
    /// `None` for plain `char` and for anything that is not an integer.
    pub fn is_unsigned(&self) -> Option<bool> {
        match self {
            CType::Int {
                sign: Sign::Unsigned,
                ..
            } => Some(true),
            CType::Int {
                sign: Sign::Signed, ..
            } => Some(false),
            _ => None,
        }
    }

    /// The conversion rank of an integer type.
    pub fn rank(&self) -> Option<Rank> {
        match self {
            CType::Int { rank, .. } => Some(*rank),
            _ => None,
        }
    }
}

/// The target's integer data model: the width of each rank and what the
/// standard aliases name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DataModel {
    /// `int` 32, `long` and pointers 64 (Linux, the BSDs, macOS).
    #[default]
    Lp64,
}

impl DataModel {
    /// Width in bits of an integer of `rank`.
    pub fn width(self, rank: Rank) -> u32 {
        match (self, rank) {
            (_, Rank::Bool) | (_, Rank::Char) => 8,
            (_, Rank::Short) => 16,
            (_, Rank::Int) => 32,
            (DataModel::Lp64, Rank::Long) => 64,
            (_, Rank::LongLong) => 64,
        }
    }

    /// The type a standard library alias names on this model, or `None` for a
    /// name that is not one. Only the aliases whose definition is fixed by the
    /// data model are listed: `int_fastN_t` and `int_leastN_t` vary by C
    /// library and are left unknown.
    pub fn standard_alias(self, name: &str) -> Option<CType> {
        use Rank::*;
        let int = |sign, rank| Some(CType::Int { sign, rank });
        let signed = |rank| int(Sign::Signed, rank);
        let unsigned = |rank| int(Sign::Unsigned, rank);
        match name {
            "int8_t" => signed(Char),
            "uint8_t" => unsigned(Char),
            "int16_t" => signed(Short),
            "uint16_t" => unsigned(Short),
            "int32_t" => signed(Int),
            "uint32_t" => unsigned(Int),
            "int64_t" | "intmax_t" | "intptr_t" | "ptrdiff_t" | "ssize_t" => signed(Long),
            "uint64_t" | "uintmax_t" | "uintptr_t" | "size_t" | "rsize_t" => unsigned(Long),
            "wchar_t" => signed(Int),
            "char16_t" => unsigned(Short),
            "char32_t" => unsigned(Int),
            "bool" => unsigned(Bool),
            "float_t" => Some(CType::Float(FloatKind::Float)),
            "double_t" => Some(CType::Float(FloatKind::Double)),
            _ => None,
        }
    }
}

/// What an expression is typed against: the typedefs and struct fields this
/// file sees ([`crate::analyze::context::VisibleTypes`]) and the data model.
pub struct TypeEnv<'a> {
    /// `typedef name -> aliased type text`.
    pub typedefs: &'a HashMap<String, String>,
    /// `struct tag or typedef name -> field -> type text`.
    pub fields: &'a HashMap<String, HashMap<String, String>>,
    /// The target's integer data model.
    pub model: DataModel,
}

impl<'a> TypeEnv<'a> {
    /// An environment over `typedefs` and `fields` with the default data
    /// model.
    pub fn new(
        typedefs: &'a HashMap<String, String>,
        fields: &'a HashMap<String, HashMap<String, String>>,
    ) -> Self {
        Self {
            typedefs,
            fields,
            model: DataModel::default(),
        }
    }
}

const QUALIFIERS: &[&str] = &[
    "const",
    "volatile",
    "restrict",
    "__restrict",
    "__restrict__",
    "_Atomic",
    "static",
    "extern",
    "register",
    "auto",
    "inline",
    "__inline",
    "__inline__",
    "_Thread_local",
    "thread_local",
    "__extension__",
];

/// Classify a type spelling -- the specifier tokens of a declaration, a cast's
/// type, a struct field's recorded type, or a typedef's right-hand side. Each
/// trailing or embedded `*` adds a pointer level.
pub fn classify_spelling(spelling: &str, env: &TypeEnv) -> Option<CType> {
    classify_spelling_depth(spelling, env, 0)
}

fn classify_spelling_depth(spelling: &str, env: &TypeEnv, depth: u32) -> Option<CType> {
    let pointers = spelling.matches('*').count();
    let base = classify_base(&spelling.replace('*', " "), env, depth)?;
    Some((0..pointers).fold(base, |t, _| CType::Pointer(Some(Box::new(t)))))
}

fn classify_base(text: &str, env: &TypeEnv, depth: u32) -> Option<CType> {
    let tokens: Vec<&str> = text
        .split_whitespace()
        .filter(|t| !QUALIFIERS.contains(t))
        .collect();
    match tokens.as_slice() {
        [] => None,
        ["struct" | "union", tag] => Some(CType::Record(Some((*tag).to_string()))),
        ["struct" | "union"] => Some(CType::Record(None)),
        ["enum", ..] => Some(CType::Enum),
        [name] if !is_keyword(name) => classify_name(name, env, depth),
        _ => classify_keywords(&tokens),
    }
}

fn is_keyword(token: &str) -> bool {
    matches!(
        token,
        "void"
            | "char"
            | "short"
            | "int"
            | "long"
            | "signed"
            | "unsigned"
            | "__signed__"
            | "__unsigned__"
            | "float"
            | "double"
            | "_Bool"
            | "_Complex"
    ) || EXTENDED_FLOAT_TYPES.contains(&token)
}

/// A typedef name: the file's or the project's typedef chain first (a project
/// may define its own `u32`), then the standard aliases, then a typedef'd
/// struct the field map knows.
fn classify_name(name: &str, env: &TypeEnv, depth: u32) -> Option<CType> {
    if depth < 16 {
        if let Some(rhs) = env.typedefs.get(name) {
            if rhs != name {
                if let Some(t) = classify_spelling_depth(rhs, env, depth + 1) {
                    return Some(t);
                }
            }
        }
    }
    let terminal = resolve_typedef_chain(name, env.typedefs);
    if let Some(t) = env.model.standard_alias(&terminal) {
        return Some(t);
    }
    if let Some(t) = env.model.standard_alias(name) {
        return Some(t);
    }
    if env.fields.contains_key(name) {
        return Some(CType::Record(Some(name.to_string())));
    }
    None
}

/// A specifier made only of C keywords, in any order (`long unsigned int`).
fn classify_keywords(tokens: &[&str]) -> Option<CType> {
    let mut unsigned = false;
    let mut signed = false;
    let (mut char_, mut short, mut int, mut long) = (0, 0, 0, 0);
    let (mut float, mut double, mut void, mut bool_) = (false, false, false, false);
    let mut extended = false;
    for &t in tokens {
        match t {
            "unsigned" | "__unsigned__" => unsigned = true,
            "signed" | "__signed__" => signed = true,
            "char" => char_ += 1,
            "short" => short += 1,
            "int" => int += 1,
            "long" => long += 1,
            "float" => float = true,
            "double" => double = true,
            "void" => void = true,
            "_Bool" => bool_ = true,
            // A complex type is not a real floating type.
            "_Complex" => return None,
            t if EXTENDED_FLOAT_TYPES.contains(&t) => extended = true,
            _ => return None,
        }
    }
    let int_words = char_ + short + int + long;
    if void {
        return (tokens.len() == 1).then_some(CType::Void);
    }
    if bool_ {
        return (tokens.len() == 1).then_some(CType::Int {
            sign: Sign::Unsigned,
            rank: Rank::Bool,
        });
    }
    if extended {
        return (tokens.len() == 1).then_some(CType::Float(FloatKind::Extended));
    }
    if float {
        return (tokens.len() == 1).then_some(CType::Float(FloatKind::Float));
    }
    if double {
        return match (long, int_words - long, signed || unsigned) {
            (0, 0, false) => Some(CType::Float(FloatKind::Double)),
            (1, 0, false) => Some(CType::Float(FloatKind::LongDouble)),
            _ => None,
        };
    }
    if signed && unsigned || int > 1 || char_ > 1 || short > 1 || long > 2 {
        return None;
    }
    let rank = match (char_, short, long) {
        (1, 0, 0) if int == 0 => Rank::Char,
        (0, 1, 0) => Rank::Short,
        (0, 0, 0) => Rank::Int,
        (0, 0, 1) => Rank::Long,
        (0, 0, 2) => Rank::LongLong,
        _ => return None,
    };
    let sign = if unsigned {
        Sign::Unsigned
    } else if signed || rank != Rank::Char {
        Sign::Signed
    } else {
        Sign::PlainChar
    };
    if int_words == 0 && !signed && !unsigned {
        return None;
    }
    Some(CType::Int { sign, rank })
}

/// The type-specifier spelling of a `declaration`, `parameter_declaration`,
/// `field_declaration` or `type_descriptor`: its specifier children, qualifiers
/// and storage class included (they are dropped when classified).
fn specifier_spelling(decl: &Node, source: &str) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    for i in 0..decl.child_count() {
        let Some(child) = decl.child(i) else {
            continue;
        };
        match child.kind() {
            "primitive_type" | "sized_type_specifier" | "type_identifier" | "type_qualifier" => {
                parts.push(get_node_text(&child, source).to_string());
            }
            "struct_specifier" | "union_specifier" => {
                let kw = if child.kind() == "struct_specifier" {
                    "struct"
                } else {
                    "union"
                };
                match child.child_by_field_name("name") {
                    Some(n) => parts.push(format!("{kw} {}", get_node_text(&n, source))),
                    None => parts.push(kw.to_string()),
                }
            }
            "enum_specifier" => parts.push("enum".to_string()),
            _ => {}
        }
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// The type of the declaration's specifiers, before any declarator applies.
pub fn classify_specifiers(decl: &Node, source: &str, env: &TypeEnv) -> Option<CType> {
    classify_spelling(&specifier_spelling(decl, source)?, env)
}

/// Apply `declarator` to `base`: `*d` makes a pointer to base, `d[N]` an array
/// of base, `d(...)` a function, parentheses pass through; the innermost name
/// ends the walk. Abstract declarators (in a cast's type) are applied the same
/// way.
fn apply_declarator(base: Option<CType>, declarator: &Node) -> Option<CType> {
    let wrap = |t: Option<CType>| t.map(Box::new);
    let applied = match declarator.kind() {
        "pointer_declarator" | "abstract_pointer_declarator" => Some(CType::Pointer(wrap(base))),
        "array_declarator" | "abstract_array_declarator" => Some(CType::Array(wrap(base))),
        "function_declarator" | "abstract_function_declarator" => Some(CType::Function(wrap(base))),
        "parenthesized_declarator" | "abstract_parenthesized_declarator" => base,
        _ => return base,
    };
    let inner = declarator.child_by_field_name("declarator").or_else(|| {
        declarator
            .named_child(0)
            .filter(|c| c.kind() != "type_qualifier")
    });
    match inner {
        Some(inner) if inner.id() != declarator.id() => apply_declarator(applied, &inner),
        _ => applied,
    }
}

/// The type `declarator` gives the object it declares in `decl` (a
/// `declaration`, `parameter_declaration` or `field_declaration`), an
/// `init_declarator` unwrapped to its declarator.
pub fn declarator_type(
    decl: &Node,
    declarator: &Node,
    source: &str,
    env: &TypeEnv,
) -> Option<CType> {
    let declarator = if declarator.kind() == "init_declarator" {
        declarator.child_by_field_name("declarator")?
    } else {
        *declarator
    };
    apply_declarator(classify_specifiers(decl, source, env), &declarator)
}

/// The declared type of the object the identifier occurrence `ident` names.
/// `None` when the occurrence does not resolve to a declaration in this file.
pub fn declared_type(ident: &Node, source: &str, env: &TypeEnv) -> Option<CType> {
    let name = get_node_text(ident, source);
    let (decl, declarator) = ast_utils::resolve_identifier_declarator(ident, name, source)?;
    // A declarator with no pointer, array or function level leaves the
    // specifier type; an unknown specifier leaves it unknown.
    apply_declarator(classify_specifiers(&decl, source, env), &declarator)
}

/// The type of a cast's `type_descriptor`.
fn type_descriptor_type(descriptor: &Node, source: &str, env: &TypeEnv) -> Option<CType> {
    let base = classify_specifiers(descriptor, source, env);
    match descriptor.child_by_field_name("declarator") {
        Some(d) => apply_declarator(base, &d),
        None => base,
    }
}

/// The type of the expression `node`, or `None` when it is not in reach.
pub fn expr_type(node: &Node, source: &str, env: &TypeEnv) -> Option<CType> {
    match node.kind() {
        "number_literal" => number_literal_type(get_node_text(node, source), env.model),
        // A character constant has type int (C11 6.4.4.4p10).
        "char_literal" => Some(char_literal_type(get_node_text(node, source), env.model)),
        "string_literal" | "concatenated_string" => {
            Some(CType::Array(Some(Box::new(CType::Int {
                sign: Sign::PlainChar,
                rank: Rank::Char,
            }))))
        }
        "true" | "false" => Some(CType::Int {
            sign: Sign::Unsigned,
            rank: Rank::Bool,
        }),
        "identifier" => declared_type(node, source, env),
        "parenthesized_expression" => expr_type(&node.named_child(0)?, source, env),
        "cast_expression" => type_descriptor_type(&node.child_by_field_name("type")?, source, env),
        "compound_literal_expression" => {
            type_descriptor_type(&node.child_by_field_name("type")?, source, env)
        }
        "sizeof_expression" | "alignof_expression" => env.model.standard_alias("size_t"),
        "unary_expression" => {
            let op = get_node_text(&node.child_by_field_name("operator")?, source);
            let operand = expr_type(&node.child_by_field_name("argument")?, source, env);
            match op {
                "!" => Some(int_type()),
                "-" | "+" | "~" => operand.and_then(promote),
                _ => None,
            }
        }
        "pointer_expression" => {
            let op = get_node_text(&node.child_by_field_name("operator")?, source);
            let operand = expr_type(&node.child_by_field_name("argument")?, source, env);
            match op {
                "&" => Some(CType::Pointer(operand.map(Box::new))),
                "*" => match operand? {
                    CType::Pointer(p) | CType::Array(p) => p.map(|b| *b),
                    f @ CType::Function(_) => Some(f),
                    _ => None,
                },
                _ => None,
            }
        }
        "update_expression" => expr_type(&node.child_by_field_name("argument")?, source, env),
        "binary_expression" => binary_type(node, source, env),
        "conditional_expression" => {
            let a = expr_type(&node.child_by_field_name("consequence")?, source, env)?;
            let b = expr_type(&node.child_by_field_name("alternative")?, source, env)?;
            if a.is_arithmetic() && b.is_arithmetic() {
                usual_arithmetic_conversions(a, b, env.model)
            } else if a == b {
                Some(a)
            } else {
                None
            }
        }
        "assignment_expression" => expr_type(&node.child_by_field_name("left")?, source, env),
        "comma_expression" => expr_type(&node.child_by_field_name("right")?, source, env),
        "subscript_expression" => {
            match expr_type(&node.child_by_field_name("argument")?, source, env)? {
                CType::Pointer(p) | CType::Array(p) => p.map(|b| *b),
                _ => None,
            }
        }
        "field_expression" => field_type(node, source, env),
        // A call has its callee's declared return type, when the callee is
        // declared where the call can see it; a library function whose header
        // was not expanded is unknown.
        "call_expression" => {
            match expr_type(&node.child_by_field_name("function")?, source, env)? {
                CType::Function(ret) => ret.map(|b| *b),
                CType::Pointer(Some(p)) => match *p {
                    CType::Function(ret) => ret.map(|b| *b),
                    _ => None,
                },
                _ => None,
            }
        }
        _ => None,
    }
}

fn int_type() -> CType {
    CType::Int {
        sign: Sign::Signed,
        rank: Rank::Int,
    }
}

/// The integer promotions (C11 6.3.1.1p2): below `int` becomes `int` (every
/// narrower type fits in a 32-bit `int`); floats are unchanged.
fn promote(t: CType) -> Option<CType> {
    match t {
        CType::Int { rank, .. } if rank < Rank::Int => Some(int_type()),
        CType::Enum => Some(int_type()),
        CType::Int { .. } | CType::Float(_) => Some(t),
        _ => None,
    }
}

/// The usual arithmetic conversions (C11 6.3.1.8) on two arithmetic types.
fn usual_arithmetic_conversions(a: CType, b: CType, model: DataModel) -> Option<CType> {
    match (&a, &b) {
        (CType::Float(x), CType::Float(y)) => {
            if *x == FloatKind::Extended || *y == FloatKind::Extended {
                return (x == y).then_some(a);
            }
            return Some(CType::Float(*x.max(y)));
        }
        (CType::Float(_), _) if b.is_arithmetic() => return Some(a),
        (_, CType::Float(_)) if a.is_arithmetic() => return Some(b),
        _ => {}
    }
    let (CType::Int { sign: sa, rank: ra }, CType::Int { sign: sb, rank: rb }) =
        (promote(a)?, promote(b)?)
    else {
        return None;
    };
    if sa == sb {
        return Some(CType::Int {
            sign: sa,
            rank: ra.max(rb),
        });
    }
    let ((su, ru), (ss, rs)) = if sa == Sign::Unsigned {
        ((sa, ra), (sb, rb))
    } else {
        ((sb, rb), (sa, ra))
    };
    if ru >= rs {
        return Some(CType::Int { sign: su, rank: ru });
    }
    if model.width(rs) > model.width(ru) {
        return Some(CType::Int { sign: ss, rank: rs });
    }
    Some(CType::Int {
        sign: Sign::Unsigned,
        rank: rs,
    })
}

fn binary_type(node: &Node, source: &str, env: &TypeEnv) -> Option<CType> {
    let op = get_node_text(&node.child_by_field_name("operator")?, source);
    if matches!(op, "<" | ">" | "<=" | ">=" | "==" | "!=" | "&&" | "||") {
        return Some(int_type());
    }
    let left = expr_type(&node.child_by_field_name("left")?, source, env);
    let right = expr_type(&node.child_by_field_name("right")?, source, env);
    match op {
        "<<" | ">>" => left.and_then(promote),
        "+" | "-" => {
            let (l, r) = (left?, right?);
            let decays = |t: &CType| match t {
                CType::Pointer(p) | CType::Array(p) => Some(CType::Pointer(p.clone())),
                _ => None,
            };
            match (decays(&l), decays(&r)) {
                (Some(_), Some(_)) if op == "-" => env.model.standard_alias("ptrdiff_t"),
                (Some(p), None) if r.is_integer() || r == CType::Enum => Some(p),
                (None, Some(p)) if op == "+" && (l.is_integer() || l == CType::Enum) => Some(p),
                (None, None) if l.is_arithmetic() && r.is_arithmetic() => {
                    usual_arithmetic_conversions(l, r, env.model)
                }
                _ => None,
            }
        }
        "*" | "/" | "%" | "&" | "|" | "^" => {
            let (l, r) = (left?, right?);
            if !(l.is_arithmetic() && r.is_arithmetic()) {
                return None;
            }
            if matches!(op, "%" | "&" | "|" | "^") && (l.is_float() || r.is_float()) {
                return None;
            }
            usual_arithmetic_conversions(l, r, env.model)
        }
        _ => None,
    }
}

/// `<math.h>` functions whose result is a real floating type by the
/// standard. Their header is not expanded when a file is parsed, so their
/// declaration is usually not in reach and [`expr_type`] answers `None` for a
/// call to one.
const MATH_FUNCTIONS: &[&str] = &[
    "sqrtf", "sqrt", "powf", "pow", "sinf", "sin", "cosf", "cos", "tanf", "tan", "logf", "log",
    "expf", "exp", "fabsf", "fabs",
];

/// The standard's return type for a call to one of the `<math.h>` functions
/// in [`MATH_FUNCTIONS`] (`float` for the `f`-suffixed ones), or `None`. For a
/// caller to consult only when [`expr_type`] has no answer: a declaration in
/// reach always wins over the name.
pub fn math_call_type(node: &Node, source: &str) -> Option<CType> {
    let mut n = *node;
    while n.kind() == "parenthesized_expression" {
        n = n.named_child(0)?;
    }
    if n.kind() != "call_expression" {
        return None;
    }
    let callee = n.child_by_field_name("function")?;
    if callee.kind() != "identifier" {
        return None;
    }
    let name = get_node_text(&callee, source);
    if !MATH_FUNCTIONS.contains(&name) {
        return None;
    }
    let kind = if name.ends_with('f') {
        FloatKind::Float
    } else {
        FloatKind::Double
    };
    Some(CType::Float(kind))
}

/// `s.f` / `p->f`: the field's recorded type in the struct the base names.
fn field_type(node: &Node, source: &str, env: &TypeEnv) -> Option<CType> {
    let field = get_node_text(&node.child_by_field_name("field")?, source);
    let base = expr_type(&node.child_by_field_name("argument")?, source, env)?;
    let record = match base {
        CType::Record(r) => r,
        CType::Pointer(Some(p)) | CType::Array(Some(p)) => match *p {
            CType::Record(r) => r,
            _ => return None,
        },
        _ => return None,
    }?;
    let spelling = env.fields.get(&record)?.get(field)?;
    classify_spelling(spelling, env)
}

/// An integer or floating constant's type (C11 6.4.4.1, 6.4.4.2).
pub fn number_literal_type(text: &str, model: DataModel) -> Option<CType> {
    let t = text.replace('\'', "");
    let lower = t.to_ascii_lowercase();
    let hex = lower.starts_with("0x");
    let binary = lower.starts_with("0b");
    let is_float = if hex {
        lower.contains('p')
    } else {
        !binary && (lower.contains('.') || lower.contains('e'))
    };
    if is_float {
        let kind = if lower.ends_with('f') {
            FloatKind::Float
        } else if lower.ends_with('l') {
            FloatKind::LongDouble
        } else {
            FloatKind::Double
        };
        return Some(CType::Float(kind));
    }
    // Integer: split the suffix off.
    let digits_end = lower
        .char_indices()
        .rev()
        .find(|(_, c)| !matches!(c, 'u' | 'l'))
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    let (digits, suffix) = lower.split_at(digits_end);
    let unsigned_suffix = suffix.contains('u');
    let longs = suffix.matches('l').count();
    if suffix.len() != usize::from(unsigned_suffix) + longs || longs > 2 {
        return None;
    }
    let (radix, body) = if hex {
        (16, &digits[2..])
    } else if binary {
        (2, &digits[2..])
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, &digits[1..])
    } else {
        (10, digits)
    };
    let value = u128::from_str_radix(body, radix).ok()?;
    let decimal = radix == 10;
    let min_rank = match longs {
        0 => Rank::Int,
        1 => Rank::Long,
        _ => Rank::LongLong,
    };
    for rank in [Rank::Int, Rank::Long, Rank::LongLong] {
        if rank < min_rank {
            continue;
        }
        let w = model.width(rank);
        if !unsigned_suffix && value < (1u128 << (w - 1)) {
            return Some(CType::Int {
                sign: Sign::Signed,
                rank,
            });
        }
        if (unsigned_suffix || !decimal) && value < (1u128 << w) {
            return Some(CType::Int {
                sign: Sign::Unsigned,
                rank,
            });
        }
    }
    None
}

fn char_literal_type(text: &str, model: DataModel) -> CType {
    let prefix = text.split('\'').next().unwrap_or("");
    match prefix {
        "L" => model.standard_alias("wchar_t"),
        "u" => model.standard_alias("char16_t"),
        "U" => model.standard_alias("char32_t"),
        _ => None,
    }
    .unwrap_or_else(int_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        parser.parse(code, None).unwrap()
    }

    /// The type of the expression in the last `return` of `code`.
    fn returned(code: &str, typedefs: &[(&str, &str)]) -> Option<CType> {
        let tree = parse(code);
        let typedefs: HashMap<String, String> = typedefs
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        let mut fields = HashMap::new();
        crate::analyze::prescan::collect_struct_definitions(&tree.root_node(), code, &mut fields);
        let env = TypeEnv::new(&typedefs, &fields);
        let ret = lang_parsing_substrate::query::find_descendants_of_kind(
            tree.root_node(),
            "return_statement",
        )
        .pop()
        .unwrap();
        expr_type(&ret.named_child(0).unwrap(), code, &env)
    }

    fn int(sign: Sign, rank: Rank) -> Option<CType> {
        Some(CType::Int { sign, rank })
    }

    #[test]
    fn specifier_tokens_in_any_order() {
        let t = returned("long f(void) { long unsigned int x; return x; }", &[]);
        assert_eq!(t, int(Sign::Unsigned, Rank::Long));
        let t = returned(
            "int f(void) { static const unsigned short s; return s; }",
            &[],
        );
        assert_eq!(t, int(Sign::Unsigned, Rank::Short));
    }

    #[test]
    fn ssize_t_is_signed_and_size_t_unsigned() {
        assert_eq!(
            returned("long f(ssize_t n) { return n; }", &[]),
            int(Sign::Signed, Rank::Long)
        );
        assert_eq!(
            returned("long f(size_t n) { return n; }", &[]),
            int(Sign::Unsigned, Rank::Long)
        );
    }

    #[test]
    fn a_name_is_not_its_spelling() {
        // `pointer` and `ushort` are identifiers, not types; `uint` is a
        // typedef only when one is visible.
        assert_eq!(
            returned("int f(int pointer) { return pointer; }", &[]),
            int(Sign::Signed, Rank::Int)
        );
        assert_eq!(returned("int f(ushort v) { return v; }", &[]), None);
        assert_eq!(
            returned("int f(uint v) { return v; }", &[("uint", "unsigned int")]),
            int(Sign::Unsigned, Rank::Int)
        );
    }

    #[test]
    fn typedef_chain_is_followed() {
        let t = returned(
            "long f(paddr_t p) { return p; }",
            &[("paddr_t", "word_t"), ("word_t", "unsigned long")],
        );
        assert_eq!(t, int(Sign::Unsigned, Rank::Long));
        let t = returned("double f(real r) { return r; }", &[("real", "double")]);
        assert_eq!(t, Some(CType::Float(FloatKind::Double)));
    }

    #[test]
    fn hex_literals_are_integers() {
        assert_eq!(
            number_literal_type("0x1f", DataModel::Lp64),
            int(Sign::Signed, Rank::Int)
        );
        assert_eq!(
            number_literal_type("0x1e5", DataModel::Lp64),
            int(Sign::Signed, Rank::Int)
        );
        assert_eq!(
            number_literal_type("0xffffffff", DataModel::Lp64),
            int(Sign::Unsigned, Rank::Int)
        );
        assert_eq!(
            number_literal_type("0x1p3", DataModel::Lp64),
            Some(CType::Float(FloatKind::Double))
        );
        assert_eq!(
            number_literal_type("1.5f", DataModel::Lp64),
            Some(CType::Float(FloatKind::Float))
        );
        assert_eq!(
            number_literal_type("1e3", DataModel::Lp64),
            Some(CType::Float(FloatKind::Double))
        );
        assert_eq!(
            number_literal_type("10ul", DataModel::Lp64),
            int(Sign::Unsigned, Rank::Long)
        );
        assert_eq!(
            number_literal_type("3000000000", DataModel::Lp64),
            int(Sign::Signed, Rank::Long)
        );
    }

    #[test]
    fn a_cast_states_the_type() {
        assert_eq!(
            returned("int f(double d) { return (int)d; }", &[]),
            int(Sign::Signed, Rank::Int)
        );
        assert_eq!(
            returned("int f(int i) { return (double)i; }", &[]),
            Some(CType::Float(FloatKind::Double))
        );
        assert!(returned("int f(int i) { return (char *)i; }", &[])
            .unwrap()
            .is_pointer());
    }

    #[test]
    fn inner_scope_does_not_type_the_outer_name() {
        let code = "int f(void) { int x = 1; int r = 0; { double x = 2.0; (void)x; } return x; }";
        assert_eq!(returned(code, &[]), int(Sign::Signed, Rank::Int));
    }

    #[test]
    fn operators() {
        assert_eq!(
            returned("int f(double a, double b) { return a < b; }", &[]),
            int(Sign::Signed, Rank::Int)
        );
        assert_eq!(
            returned("int f(double a) { return !a; }", &[]),
            int(Sign::Signed, Rank::Int)
        );
        assert!(returned("int f(double a) { return &a; }", &[])
            .unwrap()
            .is_pointer());
        assert_eq!(
            returned("int f(float a, double b) { return a * b; }", &[]),
            Some(CType::Float(FloatKind::Double))
        );
        assert_eq!(
            returned(
                "int f(unsigned short a, unsigned short b) { return a * b; }",
                &[]
            ),
            int(Sign::Signed, Rank::Int)
        );
        assert_eq!(
            returned("int f(int a, unsigned int b) { return a + b; }", &[]),
            int(Sign::Unsigned, Rank::Int)
        );
        assert_eq!(
            returned("int f(long a, unsigned int b) { return a + b; }", &[]),
            int(Sign::Signed, Rank::Long)
        );
    }

    #[test]
    fn pointers_arrays_fields() {
        assert_eq!(
            returned("int f(char **pp) { return **pp; }", &[]),
            int(Sign::PlainChar, Rank::Char)
        );
        assert!(returned("int f(char **pp) { return *pp; }", &[])
            .unwrap()
            .is_pointer());
        assert_eq!(
            returned("int f(void) { double a[4]; return a[1]; }", &[]),
            Some(CType::Float(FloatKind::Double))
        );
        let code = "struct s { unsigned int n; double d; };\n\
                    int f(struct s *p) { return p->d; }";
        assert_eq!(returned(code, &[]), Some(CType::Float(FloatKind::Double)));
        let code = "typedef struct { float v; } pt_t;\n\
                    int f(pt_t p) { return p.v; }";
        assert_eq!(returned(code, &[]), Some(CType::Float(FloatKind::Float)));
    }

    #[test]
    fn plain_char_is_neither_signed_nor_unsigned() {
        let t = returned("int f(char c) { return c; }", &[]).unwrap();
        assert_eq!(t.is_unsigned(), None);
    }

    #[test]
    fn unresolved_and_calls_are_unknown() {
        assert_eq!(returned("int f(void) { return g_unknown; }", &[]), None);
        assert_eq!(returned("int f(double x) { return sqrt(x); }", &[]), None);
        assert_eq!(
            returned(
                "double half(double); int f(double x) { return half(x); }",
                &[]
            ),
            Some(CType::Float(FloatKind::Double))
        );
        assert!(
            returned("char *name(int); int f(int x) { return name(x); }", &[])
                .unwrap()
                .is_pointer()
        );
    }
}
