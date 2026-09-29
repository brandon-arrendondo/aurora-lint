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
//! model of the target is a parameter rather than a constant. Under the
//! default, [`DataModel::Iso`], a type whose rank no model fixes (`uint32_t`,
//! `size_t`) is an [`CType::IntOfWidth`], and a promotion or conversion whose
//! result depends on a width ISO C leaves open is unknown.
//!
//! A struct field is typed from its specifiers (`struct_field_types`) with its
//! declarator shape applied (`struct_field_shapes`): the spelling alone drops
//! array-ness and pointer depth, so a field with no recorded shape is unknown.

use crate::analyze::context::VisibleTypes;
use crate::analyze::dead_regions::DeadRegions;
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::float_typing::EXTENDED_FLOAT_TYPES;
use crate::utility::cert_c::overflow_helpers::resolve_typedef_chain;
use std::cell::OnceCell;
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

pub use crate::utility::cert_c::data_model::{DataModel, Rank};

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
    /// An integer type whose rank the data model does not fix: under
    /// [`DataModel::Iso`], an exact-width type (`uint32_t`, which may be
    /// `unsigned int` or `unsigned long`) or a library type of unspecified
    /// width (`size_t`).
    IntOfWidth {
        /// Its signedness.
        sign: Sign,
        /// The fewest value and sign bits it can have.
        min_bits: u32,
        /// Its exact width, when that is known.
        max_bits: Option<u32>,
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
        matches!(self, CType::Int { .. } | CType::IntOfWidth { .. })
    }

    /// A pointer (an array is not one until it decays).
    pub fn is_pointer(&self) -> bool {
        matches!(self, CType::Pointer(_))
    }

    /// Arithmetic: an integer (enumerations included) or a real float.
    pub fn is_arithmetic(&self) -> bool {
        matches!(
            self,
            CType::Int { .. } | CType::IntOfWidth { .. } | CType::Float(_) | CType::Enum
        )
    }

    /// `Some(true)` for an unsigned integer, `Some(false)` for a signed one,
    /// `None` for plain `char` and for anything that is not an integer.
    pub fn is_unsigned(&self) -> Option<bool> {
        match self {
            CType::Int {
                sign: Sign::Unsigned,
                ..
            }
            | CType::IntOfWidth {
                sign: Sign::Unsigned,
                ..
            } => Some(true),
            CType::Int {
                sign: Sign::Signed, ..
            }
            | CType::IntOfWidth {
                sign: Sign::Signed, ..
            } => Some(false),
            _ => None,
        }
    }

    /// The conversion rank of an integer type, when the data model fixes it.
    pub fn rank(&self) -> Option<Rank> {
        match self {
            CType::Int { rank, .. } => Some(*rank),
            _ => None,
        }
    }
}

/// The type a standard library alias names on `model`, or `None` for a name
/// that is not one, or one whose type the model leaves open (`wchar_t`'s sign
/// under [`DataModel::Iso`]). Only the aliases whose definition the data
/// model fixes are listed: `int_fastN_t` and `int_leastN_t` vary by C library
/// and are left unknown.
pub fn standard_alias(model: DataModel, name: &str) -> Option<CType> {
    use Rank::*;
    let ranked = |sign, rank| Some(CType::Int { sign, rank });
    let unranked = |sign, min_bits, max_bits| {
        Some(CType::IntOfWidth {
            sign,
            min_bits,
            max_bits,
        })
    };
    // The rank the model gives a type exactly `bits` wide, or an unranked
    // type of that width.
    let exact = |sign, bits: u32| {
        [Char, Short, Int, Long, LongLong]
            .into_iter()
            .find(|r| model.exact_width(*r) == Some(bits))
            .map_or_else(|| unranked(sign, bits, Some(bits)), |r| ranked(sign, r))
    };
    // size_t and its kin: as wide as a pointer on every declared model.
    let word = |sign| match model {
        DataModel::Iso => unranked(sign, 16, None),
        DataModel::Ilp32 => ranked(sign, Int),
        DataModel::Lp64 => ranked(sign, Long),
        DataModel::Llp64 => ranked(sign, LongLong),
    };
    let at_least = |sign, bits: u32, declared: Rank| match model {
        DataModel::Iso => unranked(sign, bits, None),
        _ => ranked(sign, declared),
    };
    let signed = Sign::Signed;
    let unsigned = Sign::Unsigned;
    match name {
        "int8_t" => exact(signed, 8),
        "uint8_t" => exact(unsigned, 8),
        "int16_t" => exact(signed, 16),
        "uint16_t" => exact(unsigned, 16),
        "int32_t" => exact(signed, 32),
        "uint32_t" => exact(unsigned, 32),
        "int64_t" => exact(signed, 64),
        "uint64_t" => exact(unsigned, 64),
        // At least 64 bits, and 64 on every declared model.
        "intmax_t" if model == DataModel::Iso => unranked(signed, 64, None),
        "uintmax_t" if model == DataModel::Iso => unranked(unsigned, 64, None),
        "intmax_t" => exact(signed, 64),
        "uintmax_t" => exact(unsigned, 64),
        "intptr_t" | "ptrdiff_t" | "ssize_t" => word(signed),
        "uintptr_t" | "size_t" | "rsize_t" => word(unsigned),
        "wchar_t" => match model {
            DataModel::Iso => None,
            DataModel::Llp64 => ranked(unsigned, Short),
            DataModel::Ilp32 | DataModel::Lp64 => ranked(signed, Int),
        },
        "char16_t" => at_least(unsigned, 16, Short),
        "char32_t" => at_least(unsigned, 32, Int),
        "bool" => ranked(unsigned, Bool),
        "float_t" => Some(CType::Float(FloatKind::Float)),
        "double_t" => Some(CType::Float(FloatKind::Double)),
        _ => None,
    }
}

/// What an expression is typed against: the typedefs and struct fields this
/// file sees ([`VisibleTypes`]) and the data model.
///
/// Built once per file: it memoizes the file's own function definitions on
/// first use.
pub struct TypeEnv<'a> {
    /// `typedef name -> aliased type text`.
    pub typedefs: &'a HashMap<String, String>,
    /// `struct tag or typedef name -> field -> type text`.
    pub fields: &'a HashMap<String, HashMap<String, String>>,
    /// `struct tag or typedef name -> field -> declarator shape`, for the
    /// same fields.
    pub shapes: &'a HashMap<String, HashMap<String, String>>,
    /// `typedef name -> struct/union tag`, for `typedef struct Tag Alias;`.
    pub struct_aliases: &'a HashMap<String, String>,
    /// The target's integer data model.
    pub model: DataModel,
    /// `name -> return type` for the functions this file defines; see
    /// [`file_function_type`].
    file_functions: OnceCell<HashMap<String, Option<CType>>>,
}

impl<'a> TypeEnv<'a> {
    /// An environment over these tables under `model`.
    pub fn new(
        typedefs: &'a HashMap<String, String>,
        fields: &'a HashMap<String, HashMap<String, String>>,
        shapes: &'a HashMap<String, HashMap<String, String>>,
        struct_aliases: &'a HashMap<String, String>,
        model: DataModel,
    ) -> Self {
        Self {
            typedefs,
            fields,
            shapes,
            struct_aliases,
            model,
            file_functions: OnceCell::new(),
        }
    }

    /// An environment over what one file sees, under `model` (the settings'
    /// `data_model`).
    pub fn visible(types: &'a VisibleTypes, model: DataModel) -> Self {
        Self::new(
            &types.typedef_types,
            &types.struct_field_types,
            &types.struct_field_shapes,
            &types.struct_typedef_aliases,
            model,
        )
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
/// struct the field map knows, by its own name or as an alias of a tag.
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
    if let Some(t) = standard_alias(env.model, &terminal) {
        return Some(t);
    }
    if let Some(t) = standard_alias(env.model, name) {
        return Some(t);
    }
    if env.fields.contains_key(name) {
        return Some(CType::Record(Some(name.to_string())));
    }
    // `typedef struct gauge gauge_t;` files the fields under the tag only.
    if let Some(tag) = env.struct_aliases.get(name) {
        if env.fields.contains_key(tag) {
            return Some(CType::Record(Some(tag.clone())));
        }
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

/// The derivations `declarator` applies to its specifier type, outermost
/// first: `*` a pointer, `[` an array, `(` a function; parentheses add none.
/// The innermost name ends the walk. Abstract declarators (in a cast's type)
/// are read the same way. `double *v[4]` is `"*["`, which [`apply_shape`]
/// makes an array of pointers to `double`: the order the declarator nests in,
/// not the order its tokens are written in.
pub fn declarator_shape(declarator: &Node) -> String {
    let mut shape = String::new();
    let mut current = *declarator;
    loop {
        match current.kind() {
            "pointer_declarator" | "abstract_pointer_declarator" => shape.push('*'),
            "array_declarator" | "abstract_array_declarator" => shape.push('['),
            "function_declarator" | "abstract_function_declarator" => shape.push('('),
            "parenthesized_declarator" | "abstract_parenthesized_declarator" => {}
            _ => return shape,
        }
        let inner = current.child_by_field_name("declarator").or_else(|| {
            current
                .named_child(0)
                .filter(|c| c.kind() != "type_qualifier")
        });
        match inner {
            Some(inner) if inner.id() != current.id() => current = inner,
            _ => return shape,
        }
    }
}

/// `base` with the derivations of a [`declarator_shape`] applied. An unknown
/// base stays unknown inside them: a pointer to something, not nothing.
pub fn apply_shape(base: Option<CType>, shape: &str) -> Option<CType> {
    shape.chars().fold(base, |t, c| {
        let inner = t.map(Box::new);
        match c {
            '*' => Some(CType::Pointer(inner)),
            '[' => Some(CType::Array(inner)),
            '(' => Some(CType::Function(inner)),
            _ => inner.map(|b| *b),
        }
    })
}

/// Apply `declarator` to `base`: `*d` makes a pointer to base, `d[N]` an array
/// of base, `d(...)` a function, parentheses pass through.
fn apply_declarator(base: Option<CType>, declarator: &Node) -> Option<CType> {
    apply_shape(base, &declarator_shape(declarator))
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

/// The type of the function this file DEFINES under the callee's name, for a
/// call whose callee resolves to no declaration: a `static` helper defined
/// above its caller with no prototype. Only the translation unit's own
/// file-scope definitions are searched (through preprocessor arms, never into
/// a function body), so a name this file neither declares nor defines stays
/// unknown. A definition in a platform-dead arm ([`DeadRegions`]) does not
/// count; when the live definitions of a name disagree (`double scale(...)`
/// under one `#if` arm, `int scale(...)` under the other), which one is
/// compiled is not known here, so the answer is unknown.
fn file_function_type(callee: &Node, source: &str, env: &TypeEnv) -> Option<CType> {
    let name = get_node_text(callee, source);
    env.file_functions
        .get_or_init(|| file_function_types(callee, source, env))
        .get(name)
        .cloned()
        .flatten()
}

/// Every function the file containing `node` defines, by name: its type when
/// its live definitions agree, `None` when they do not.
fn file_function_types(node: &Node, source: &str, env: &TypeEnv) -> HashMap<String, Option<CType>> {
    let mut root = *node;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let dead = DeadRegions::of(source);
    let mut types: HashMap<String, Option<CType>> = HashMap::new();
    let mut pending = vec![root];
    while let Some(scope) = pending.pop() {
        for i in 0..scope.named_child_count() {
            let Some(child) = scope.named_child(i) else {
                continue;
            };
            match child.kind() {
                "function_definition" if !dead.contains_node(&child) => {
                    let Some(declarator) = child.child_by_field_name("declarator") else {
                        continue;
                    };
                    let name = ast_utils::get_identifier_from_declarator(&declarator, source);
                    let t = declarator_type(&child, &declarator, source, env);
                    types
                        .entry(name)
                        .and_modify(|seen| {
                            if *seen != t {
                                *seen = None;
                            }
                        })
                        .or_insert(t);
                }
                k if k.starts_with("preproc_") => pending.push(child),
                _ => {}
            }
        }
    }
    types
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
        "char_literal" => char_literal_type(get_node_text(node, source), env.model),
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
        "sizeof_expression" | "alignof_expression" => standard_alias(env.model, "size_t"),
        "unary_expression" => {
            let op = get_node_text(&node.child_by_field_name("operator")?, source);
            let operand = expr_type(&node.child_by_field_name("argument")?, source, env);
            match op {
                "!" => Some(int_type()),
                "-" | "+" | "~" => operand.and_then(|t| promote(t, env.model)),
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
        // was not expanded is unknown, apart from the `<math.h>` functions,
        // whose type the standard fixes.
        "call_expression" => {
            let callee = node.child_by_field_name("function")?;
            let callee_type = expr_type(&callee, source, env).or_else(|| {
                (callee.kind() == "identifier")
                    .then(|| file_function_type(&callee, source, env))
                    .flatten()
            });
            let Some(callee_type) = callee_type else {
                return math_call_type(node, source);
            };
            match callee_type {
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

/// The integer promotions (C11 6.3.1.1p2): a type below `int` becomes `int`
/// when `int` holds all its values, else `unsigned int`; floats are
/// unchanged. `None` when `model` leaves that open: under
/// [`DataModel::Iso`] an `unsigned short` is as wide as `int` on a 16-bit
/// target, so it may promote to either.
fn promote(t: CType, model: DataModel) -> Option<CType> {
    let unsigned_int = CType::Int {
        sign: Sign::Unsigned,
        rank: Rank::Int,
    };
    match t {
        CType::Int {
            rank: Rank::Bool, ..
        }
        | CType::Enum => Some(int_type()),
        // A lower rank never has a greater range (6.3.1.1p1), so `int` holds
        // every signed type below it.
        CType::Int {
            sign: Sign::Signed,
            rank,
        } if rank < Rank::Int => Some(int_type()),
        CType::Int { rank, .. } if rank < Rank::Int => {
            let (w, int) = (model.exact_width(rank)?, model.exact_width(Rank::Int)?);
            Some(if w < int { int_type() } else { unsigned_int })
        }
        CType::Int { .. } | CType::Float(_) => Some(t),
        // Promoted, a signed type no wider than `int` is guaranteed to be is
        // `int` (it is either below `int` or `int` itself), and so is an
        // unsigned one narrower than that.
        CType::IntOfWidth {
            sign: Sign::Signed,
            max_bits: Some(bits),
            ..
        } if bits <= model.min_width(Rank::Int) => Some(int_type()),
        CType::IntOfWidth {
            sign: Sign::Unsigned,
            max_bits: Some(bits),
            ..
        } if bits < model.min_width(Rank::Int) => Some(int_type()),
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
        (promote(a, model)?, promote(b, model)?)
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
    // The signed type wins only if it holds every value of the unsigned
    // one, which needs both widths.
    if model.exact_width(rs)? > model.exact_width(ru)? {
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
        "<<" | ">>" => left.and_then(|t| promote(t, env.model)),
        "+" | "-" => {
            let (l, r) = (left?, right?);
            let decays = |t: &CType| match t {
                CType::Pointer(p) | CType::Array(p) => Some(CType::Pointer(p.clone())),
                _ => None,
            };
            match (decays(&l), decays(&r)) {
                (Some(_), Some(_)) if op == "-" => standard_alias(env.model, "ptrdiff_t"),
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
/// declaration is usually not in reach; [`expr_type`] types a call to one by
/// this table when nothing the file declares or defines types the callee.
const MATH_FUNCTIONS: &[&str] = &[
    "sqrtf", "sqrt", "powf", "pow", "sinf", "sin", "cosf", "cos", "tanf", "tan", "logf", "log",
    "expf", "exp", "fabsf", "fabs",
];

/// The standard's return type for a call to one of the `<math.h>` functions
/// in [`MATH_FUNCTIONS`] (`float` for the `f`-suffixed ones), or `None`. The
/// names are reserved to the library (C11 7.1.3), so the name answers only
/// when no declaration in reach does: [`expr_type`] consults it last.
fn math_call_type(node: &Node, source: &str) -> Option<CType> {
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

/// `s.f` / `p->f`: the field's type in the struct the base names -- its
/// recorded specifiers with its declarator shape applied. The specifier
/// spelling alone is not the type (`double v[4]` and `double **p` are filed
/// as `double` and `double *`), so a field with no recorded shape is unknown.
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
    let shape = env.shapes.get(&record)?.get(field)?;
    // The spelling's ` *` stands for the pointer levels the shape states.
    let base = classify_spelling(&spelling.replace('*', " "), env);
    match shape.strip_prefix(':') {
        Some(width) => bit_field_type(base?, width, env.model),
        None => apply_shape(base, shape),
    }
}

/// The type a bit-field's value has in an expression. A bit-field narrower
/// than `int` promotes to `int` whatever its declared signedness, since `int`
/// holds every value it can have (C11 6.3.1.1p2), so `o->type != type` with
/// `unsigned type : 4` compares two ints. One exactly as wide as `int` keeps
/// its declared type. A width that is not a decimal constant (a macro), or
/// a bit-field of a type other than `int`, `unsigned int` or `_Bool`, whose
/// promotion is implementation-defined, is unknown. One `model` leaves as
/// possibly as wide as `int` (16 bits or more under [`DataModel::Iso`]) is
/// an [`CType::IntOfWidth`] of exactly its width: it promotes to `int`, or
/// keeps its declared type, depending on the target.
fn bit_field_type(declared: CType, width: &str, model: DataModel) -> Option<CType> {
    let width: u32 = width.parse().ok()?;
    match declared {
        CType::Int { rank, .. }
            if rank == Rank::Bool || (rank == Rank::Int && width < model.min_width(Rank::Int)) =>
        {
            Some(int_type())
        }
        CType::Int {
            rank: Rank::Int, ..
        } if model.exact_width(Rank::Int) == Some(width) => Some(declared),
        CType::Int {
            rank: Rank::Int,
            sign,
        } if model.exact_width(Rank::Int).is_none() => Some(CType::IntOfWidth {
            sign,
            min_bits: width,
            max_bits: Some(width),
        }),
        _ => None,
    }
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
        // Where the width is not fixed, a value inside the guaranteed range
        // has this type everywhere, and one outside it has this type or a
        // later one depending on the target.
        let w = model.min_width(rank);
        let exact = model.exact_width(rank).is_some();
        if !unsigned_suffix && value < (1u128 << (w - 1)) {
            return Some(CType::Int {
                sign: Sign::Signed,
                rank,
            });
        }
        if (unsigned_suffix || !decimal) && value < (1u128 << w) {
            if !unsigned_suffix && !exact {
                return None;
            }
            return Some(CType::Int {
                sign: Sign::Unsigned,
                rank,
            });
        }
        if !exact {
            return None;
        }
    }
    None
}

fn char_literal_type(text: &str, model: DataModel) -> Option<CType> {
    let prefix = text.split('\'').next().unwrap_or("");
    match prefix {
        "L" => standard_alias(model, "wchar_t"),
        "u" => standard_alias(model, "char16_t"),
        "U" => standard_alias(model, "char32_t"),
        _ => Some(int_type()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        parser.parse(code, None).unwrap()
    }

    /// The type of the expression in the last `return` of `code`, on LP64.
    fn returned(code: &str, typedefs: &[(&str, &str)]) -> Option<CType> {
        returned_on(DataModel::Lp64, code, typedefs)
    }

    /// The type of the expression in the last `return` of `code`, on `model`.
    fn returned_on(model: DataModel, code: &str, typedefs: &[(&str, &str)]) -> Option<CType> {
        let tree = parse(code);
        let typedefs: HashMap<String, String> = typedefs
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        let (mut fields, mut shapes, mut aliases) =
            (HashMap::new(), HashMap::new(), HashMap::new());
        let root = tree.root_node();
        crate::analyze::prescan::collect_struct_tables(&root, code, &mut fields, &mut shapes);
        crate::analyze::prescan::collect_struct_typedef_aliases(&root, code, &mut aliases);
        let env = TypeEnv::new(&typedefs, &fields, &shapes, &aliases, model);
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
    fn a_field_has_its_declarator_shape() {
        let double = || Some(Box::new(CType::Float(FloatKind::Double)));
        let code = "struct buf { double v[4]; };\n\
                    int f(struct buf *a) { return a->v; }";
        assert_eq!(returned(code, &[]), Some(CType::Array(double())));
        let code = "struct mat { double **rows; };\n\
                    int f(struct mat *a) { return *a->rows; }";
        assert_eq!(returned(code, &[]), Some(CType::Pointer(double())));
        // Array of pointers, not pointer to array.
        let code = "struct t { double *p[4]; };\n\
                    int f(struct t *a) { return a->p[0]; }";
        assert_eq!(returned(code, &[]), Some(CType::Pointer(double())));
        // The ` *` a sibling declarator put in the spelling is not this one's.
        let code = "struct u { double *a, b; };\n\
                    int f(struct u *s) { return s->b; }";
        assert_eq!(returned(code, &[]), Some(CType::Float(FloatKind::Double)));
    }

    #[test]
    fn a_narrow_bit_field_is_an_int() {
        let code =
            "struct o { unsigned type : 4; unsigned full : 32; unsigned lru : LRU_BITS; };\n\
                    int f(struct o *p) { return p->type; }";
        assert_eq!(returned(code, &[]), int(Sign::Signed, Rank::Int));
        let code = "struct o { unsigned type : 4; unsigned full : 32; };\n\
                    int f(struct o *p) { return p->full; }";
        assert_eq!(returned(code, &[]), int(Sign::Unsigned, Rank::Int));
        let code = "struct o { unsigned lru : LRU_BITS; };\n\
                    int f(struct o *p) { return p->lru; }";
        assert_eq!(returned(code, &[]), None);
    }

    #[test]
    fn a_field_with_no_recorded_shape_is_unknown() {
        let tree = parse("int f(struct s *p) { return p->d; }");
        let code = "int f(struct s *p) { return p->d; }";
        let fields: HashMap<String, HashMap<String, String>> = [(
            "s".to_string(),
            [("d".to_string(), "double".to_string())].into(),
        )]
        .into();
        let (typedefs, shapes, aliases) = (HashMap::new(), HashMap::new(), HashMap::new());
        let env = TypeEnv::new(&typedefs, &fields, &shapes, &aliases, DataModel::Lp64);
        let ret = lang_parsing_substrate::query::find_descendants_of_kind(
            tree.root_node(),
            "return_statement",
        )
        .pop()
        .unwrap();
        assert_eq!(expr_type(&ret.named_child(0).unwrap(), code, &env), None);
    }

    #[test]
    fn a_bodyless_struct_typedef_names_the_tags_fields() {
        let code = "struct gauge { double ratio; };\n\
                    typedef struct gauge gauge_t;\n\
                    int f(const gauge_t *p) { return p->ratio; }";
        assert_eq!(returned(code, &[]), Some(CType::Float(FloatKind::Double)));
    }

    #[test]
    fn plain_char_is_neither_signed_nor_unsigned() {
        let t = returned("int f(char c) { return c; }", &[]).unwrap();
        assert_eq!(t.is_unsigned(), None);
    }

    #[test]
    fn unresolved_and_calls_are_unknown() {
        assert_eq!(returned("int f(void) { return g_unknown; }", &[]), None);
        // A `<math.h>` function the file does not declare has the standard's
        // type, inside an operand as well as at its top.
        assert_eq!(
            returned("int f(double x) { return sqrt(x); }", &[]),
            Some(CType::Float(FloatKind::Double))
        );
        assert_eq!(
            returned("int f(float x) { return sqrtf(x) * 2; }", &[]),
            Some(CType::Float(FloatKind::Float))
        );
        // A declaration in reach wins over the name.
        assert_eq!(
            returned("int sqrt(int); int f(int x) { return sqrt(x); }", &[]),
            Some(CType::Int {
                sign: Sign::Signed,
                rank: Rank::Int
            })
        );
        assert_eq!(returned("int f(double x) { return frob(x); }", &[]), None);
        assert_eq!(
            returned(
                "double half(double); int f(double x) { return half(x); }",
                &[]
            ),
            Some(CType::Float(FloatKind::Double))
        );
        assert_eq!(
            returned(
                "static double ceil2(double v) { return v; }\nint f(double x) { return ceil2(x); }",
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

    #[test]
    fn definitions_that_disagree_across_arms_are_unknown() {
        let code = "#ifdef USE_FLOAT\n\
                    static double scale(double v) { return v * 2.0; }\n\
                    #else\n\
                    static int scale(int v) { return v * 2; }\n\
                    #endif\n\
                    int same(int a) { return scale(a); }";
        assert_eq!(returned(code, &[]), None);
        let code = "#ifdef USE_FLOAT\n\
                    static double scale(double v) { return v * 2.0; }\n\
                    #else\n\
                    static double scale(double v) { return v + v; }\n\
                    #endif\n\
                    int same(double a) { return scale(a); }";
        assert_eq!(returned(code, &[]), Some(CType::Float(FloatKind::Double)));
        // A definition in a dead arm is not compiled, so it does not count.
        let code = "#if 0\n\
                    static int scale(int v) { return v * 2; }\n\
                    #endif\n\
                    static double scale(double v) { return v * 2.0; }\n\
                    int same(double a) { return scale(a); }";
        assert_eq!(returned(code, &[]), Some(CType::Float(FloatKind::Double)));
    }

    #[test]
    fn iso_leaves_the_rank_of_a_width_alias_open() {
        let iso = |code: &str| returned_on(DataModel::Iso, code, &[]);
        let width = |sign, min_bits, max_bits| {
            Some(CType::IntOfWidth {
                sign,
                min_bits,
                max_bits,
            })
        };
        assert_eq!(
            iso("long f(uint32_t n) { return n; }"),
            width(Sign::Unsigned, 32, Some(32))
        );
        assert_eq!(
            iso("long f(size_t n) { return n; }"),
            width(Sign::Unsigned, 16, None)
        );
        assert_eq!(
            iso("long f(uint8_t n) { return n; }"),
            width(Sign::Unsigned, 8, Some(8))
        );
        assert_eq!(
            iso("int f(uint8_t n) { return -n; }"),
            int(Sign::Signed, Rank::Int)
        );
        assert_eq!(iso("long f(wchar_t c) { return c; }"), None);
        // Still an integer, for a caller that asks only that.
        assert!(iso("long f(size_t n) { return n; }").unwrap().is_integer());
        // A declared model names the rank.
        assert_eq!(
            returned_on(DataModel::Llp64, "long f(size_t n) { return n; }", &[]),
            int(Sign::Unsigned, Rank::LongLong)
        );
        assert_eq!(
            returned_on(DataModel::Llp64, "long f(uint64_t n) { return n; }", &[]),
            int(Sign::Unsigned, Rank::LongLong)
        );
    }

    #[test]
    fn iso_types_a_promotion_only_where_every_width_agrees() {
        let iso = |code: &str| returned_on(DataModel::Iso, code, &[]);
        // A signed narrow type always fits int.
        assert_eq!(
            iso("int f(short a) { return -a; }"),
            int(Sign::Signed, Rank::Int)
        );
        // unsigned short is as wide as int on a 16-bit target.
        assert_eq!(iso("int f(unsigned short a) { return -a; }"), None);
        assert_eq!(
            returned("int f(unsigned short a) { return -a; }", &[]),
            int(Sign::Signed, Rank::Int)
        );
        // long wins over unsigned int only if it is wider.
        assert_eq!(iso("long f(long a, unsigned b) { return a + b; }"), None);
        assert_eq!(
            returned("long f(long a, unsigned b) { return a + b; }", &[]),
            int(Sign::Signed, Rank::Long)
        );
        assert_eq!(
            returned_on(
                DataModel::Llp64,
                "long f(long a, unsigned b) { return a + b; }",
                &[]
            ),
            int(Sign::Unsigned, Rank::Long)
        );
    }

    #[test]
    fn iso_types_a_literal_only_inside_the_guaranteed_range() {
        let signed = |rank| int(Sign::Signed, rank);
        assert_eq!(
            number_literal_type("32767", DataModel::Iso),
            signed(Rank::Int)
        );
        // int or long, depending on the target.
        assert_eq!(number_literal_type("40000", DataModel::Iso), None);
        assert_eq!(
            number_literal_type("40000L", DataModel::Iso),
            signed(Rank::Long)
        );
        assert_eq!(
            number_literal_type("40000u", DataModel::Iso),
            int(Sign::Unsigned, Rank::Int)
        );
        // int or unsigned int.
        assert_eq!(number_literal_type("0xffff", DataModel::Iso), None);
        assert_eq!(
            number_literal_type("40000", DataModel::Lp64),
            signed(Rank::Int)
        );
    }
}
