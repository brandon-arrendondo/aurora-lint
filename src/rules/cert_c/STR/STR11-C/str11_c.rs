// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! STR11-C: Do not specify the bound of a character array initialized with a string literal
//!
//! ## What is reported
//!
//! CERT's whole form: an explicit bound on a character array initialized
//! with a string literal, unless the bound is larger than the literal with
//! its terminating null character (EX2). Three cases, each with its own
//! message:
//!
//! - **too short** (`char s[2] = "abc"`): a constraint violation;
//! - **exact fit** (`char s[3] = "abc"`): legal C, but the array holds no
//!   terminating null character;
//! - **bound equals the size** (`char s[4] = "abc"`): terminated, but the
//!   bound restates what the initializer already says, and drifts from it
//!   when the literal is edited.
//!
//! EX1 (an array that is deliberately not a string) is credited only for a
//! declared intent the compiler can check, `__attribute__((nonstring))` or
//! `[[gnu::nonstring]]`, and only for the exact fit it allows. A comment
//! saying the array is not a string does not count.
//!
//! The literal is measured as the compiler lays it out: elements per
//! encoding prefix (UTF-8 bytes for none and `u8`, UTF-16 units for `u`, one
//! per character for `U` and `L`), an octal or hexadecimal escape as one
//! element, and adjacent literals joined. The bound is evaluated as a
//! constant expression (`3u`, `N + 1`, an enumerator, a macro). Braced
//! literals (`{"abc"}`), arrays of arrays and members of a structure or
//! union defined in the file are followed through their initializers.
//!
//! When an `L` literal holds a character outside the Basic Multilingual
//! Plane its element count depends on the width of `wchar_t`, and it is not
//! measured.

use crate::analyze::const_eval::{self, MacroConstantMap};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::sync::Arc;
use tree_sitter::Node;

#[derive(Default)]
pub struct Str11C {
    project_macros: RefCell<Arc<MacroConstantMap>>,
    settings: RefCell<Arc<AnalysisSettings>>,
}

impl CertRule for Str11C {
    fn rule_id(&self) -> &'static str {
        "STR11-C"
    }

    fn cert_id(&self) -> &'static str {
        "STR11"
    }

    fn description(&self) -> &'static str {
        "Do not specify the bound of a character array initialized with a string literal"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_macros.borrow_mut() = context.macro_constants.clone();
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        *self.settings.borrow_mut() = Arc::clone(settings);
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        let macros = const_eval::merged_macro_constants(
            &self.project_macros.borrow(),
            root,
            source,
            self.settings.borrow().facts,
        );
        let cx = Cx {
            root: *root,
            source,
            macros: &macros,
        };
        let mut violations = Vec::new();
        for decl in query::find_descendants_of_kind(*root, "declaration") {
            let Some(base) = decl.child_by_field_name("type") else {
                continue;
            };
            let nonstring = has_nonstring_attribute(&decl, source);
            let mut cursor = decl.walk();
            for init in decl.children(&mut cursor) {
                if init.kind() != "init_declarator" {
                    continue;
                }
                let (Some(declarator), Some(value)) = (
                    init.child_by_field_name("declarator"),
                    init.child_by_field_name("value"),
                ) else {
                    continue;
                };
                let base_shape = cx.base_shape(&base, 0);
                let shape = cx.declarator_shape(&declarator, base_shape, nonstring);
                cx.walk(&shape, &value, Some(&init), &mut violations, 0);
            }
        }
        violations
    }
}

impl Str11C {
    pub fn new() -> Self {
        Self::default()
    }
}

/// The type an initializer is matched against, as far as STR11-C needs it.
enum Shape<'a> {
    /// An array: its bound (`None` when the initializer sizes it), element
    /// shape, and whether its declaration carries `nonstring`.
    Array {
        bound: Option<Node<'a>>,
        element: Box<Shape<'a>>,
        nonstring: bool,
    },
    /// A structure or union defined in the file: its members in order.
    Record(Vec<(String, Shape<'a>)>),
    /// Anything else: a scalar, a pointer, or a type not defined in reach.
    Other,
}

struct Cx<'a, 's> {
    root: Node<'a>,
    source: &'s str,
    macros: &'s MacroConstantMap,
}

/// Bound on following typedefs and nested records.
const MAX_DEPTH: usize = 16;

impl<'a, 's> Cx<'a, 's> {
    /// The shape a type specifier names: a structure or union whose members
    /// the file defines (inline, by tag, or through a typedef), else `Other`.
    fn base_shape(&self, spec: &Node<'a>, depth: usize) -> Shape<'a> {
        if depth > MAX_DEPTH {
            return Shape::Other;
        }
        match spec.kind() {
            "struct_specifier" | "union_specifier" => {
                let body = spec.child_by_field_name("body").or_else(|| {
                    let tag = get_node_text(&spec.child_by_field_name("name")?, self.source);
                    query::find_first_descendant(self.root, |n| {
                        n.kind() == spec.kind()
                            && n.child_by_field_name("body").is_some()
                            && n.child_by_field_name("name")
                                .is_some_and(|t| get_node_text(&t, self.source) == tag)
                    })
                    .and_then(|d| d.child_by_field_name("body"))
                });
                match body {
                    Some(b) => self.record_shape(&b, depth),
                    None => Shape::Other,
                }
            }
            "type_identifier" => {
                let name = get_node_text(spec, self.source);
                let typedef = query::find_first_descendant(self.root, |n| {
                    n.kind() == "type_definition"
                        && n.children_by_field_name("declarator", &mut n.walk())
                            .any(|d| typedef_name(&d, self.source) == Some(name))
                });
                match typedef {
                    Some(t) => {
                        let Some(ty) = t.child_by_field_name("type") else {
                            return Shape::Other;
                        };
                        let base = self.base_shape(&ty, depth + 1);
                        let declarator = t
                            .children_by_field_name("declarator", &mut t.walk())
                            .find(|d| typedef_name(d, self.source) == Some(name));
                        match declarator {
                            Some(d) => self.declarator_shape(&d, base, false),
                            None => Shape::Other,
                        }
                    }
                    None => Shape::Other,
                }
            }
            _ => Shape::Other,
        }
    }

    fn record_shape(&self, body: &Node<'a>, depth: usize) -> Shape<'a> {
        let mut members = Vec::new();
        let mut cursor = body.walk();
        for field in body.children(&mut cursor) {
            if field.kind() != "field_declaration" {
                continue;
            }
            let Some(ty) = field.child_by_field_name("type") else {
                return Shape::Other;
            };
            let nonstring = has_nonstring_attribute(&field, self.source);
            let declarators: Vec<Node> = field
                .children_by_field_name("declarator", &mut field.walk())
                .collect();
            if declarators.is_empty() {
                // An anonymous structure or union: its members are the
                // enclosing record's, which this walk does not flatten.
                return Shape::Other;
            }
            for d in declarators {
                let base = self.base_shape(&ty, depth + 1);
                let name = query::find_first_descendant(d, |n| n.kind() == "field_identifier")
                    .or_else(|| (d.kind() == "field_identifier").then_some(d))
                    .map(|n| get_node_text(&n, self.source).to_string())
                    .unwrap_or_default();
                members.push((name, self.declarator_shape(&d, base, nonstring)));
            }
        }
        Shape::Record(members)
    }

    /// Apply a declarator to `base`, inside out: `char *a[3]` is an array of
    /// pointers, `char a[2][4]` an array of two arrays of four.
    fn declarator_shape(&self, d: &Node<'a>, base: Shape<'a>, nonstring: bool) -> Shape<'a> {
        match d.kind() {
            "array_declarator" => {
                let inner = d.child_by_field_name("declarator");
                let shape = Shape::Array {
                    bound: d.child_by_field_name("size"),
                    element: Box::new(base),
                    nonstring,
                };
                match inner {
                    Some(i) => self.declarator_shape(&i, shape, nonstring),
                    None => shape,
                }
            }
            "pointer_declarator" | "function_declarator" => {
                match d.child_by_field_name("declarator") {
                    Some(i) => self.declarator_shape(&i, Shape::Other, nonstring),
                    None => Shape::Other,
                }
            }
            "parenthesized_declarator" | "init_declarator" | "attributed_declarator" => {
                match d.named_child(0) {
                    Some(i) => self.declarator_shape(&i, base, nonstring),
                    None => base,
                }
            }
            _ => base,
        }
    }

    /// Match `value` against `shape`, reporting each string literal that
    /// initializes a bounded character array.
    fn walk(
        &self,
        shape: &Shape<'a>,
        value: &Node<'a>,
        site: Option<&Node<'a>>,
        out: &mut Vec<RuleViolation>,
        depth: usize,
    ) {
        if depth > MAX_DEPTH {
            return;
        }
        match shape {
            Shape::Array {
                bound,
                element,
                nonstring,
            } => {
                if is_string(value) {
                    if matches!(**element, Shape::Other) {
                        self.check_literal(*bound, value, *nonstring, site.unwrap_or(value), out);
                    }
                    return;
                }
                if value.kind() != "initializer_list" {
                    return;
                }
                let elements = list_elements(value);
                // `char s[4] = {"abc"}`: a braced literal.
                if matches!(**element, Shape::Other) {
                    if let [only] = elements.as_slice() {
                        if is_string(only) {
                            self.check_literal(*bound, only, *nonstring, only, out);
                        }
                    }
                    return;
                }
                for e in elements {
                    let v = match e.kind() {
                        "initializer_pair" => match e.child_by_field_name("value") {
                            Some(v) => v,
                            None => continue,
                        },
                        _ => e,
                    };
                    if !is_string(&v) && v.kind() != "initializer_list" {
                        // Brace elision: the flattened elements no longer
                        // line up with the shape.
                        return;
                    }
                    self.walk(element, &v, None, out, depth + 1);
                }
            }
            Shape::Record(members) => {
                if value.kind() != "initializer_list" {
                    return;
                }
                let mut next = 0;
                for e in list_elements(value) {
                    let (index, v) = if e.kind() == "initializer_pair" {
                        let Some(name) = field_designator(&e, self.source) else {
                            return;
                        };
                        let Some(i) = members.iter().position(|(n, _)| *n == name) else {
                            return;
                        };
                        let Some(v) = e.child_by_field_name("value") else {
                            return;
                        };
                        (i, v)
                    } else {
                        (next, e)
                    };
                    let Some((_, member)) = members.get(index) else {
                        return;
                    };
                    if matches!(member, Shape::Array { .. } | Shape::Record(_))
                        && !is_string(&v)
                        && v.kind() != "initializer_list"
                    {
                        return;
                    }
                    self.walk(member, &v, None, out, depth + 1);
                    next = index + 1;
                }
            }
            Shape::Other => {}
        }
    }

    fn check_literal(
        &self,
        bound: Option<Node<'a>>,
        literal: &Node<'a>,
        nonstring: bool,
        site: &Node<'a>,
        out: &mut Vec<RuleViolation>,
    ) {
        let Some(bound_node) = bound else {
            return;
        };
        let Some(bound) = const_eval::try_evaluate_expr(&bound_node, self.source, self.macros)
        else {
            return;
        };
        let Some(size) = literal_size(literal, self.source) else {
            return;
        };
        let (Ok(bound), Ok(size)) = (u64::try_from(bound), u64::try_from(size)) else {
            return;
        };
        let literal_text = get_node_text(literal, self.source);
        let bound_text = get_node_text(&bound_node, self.source);
        let message = if bound > size {
            return;
        } else if bound == size {
            format!(
                "Character array bound [{bound_text}] restates the size of string literal \
                 {literal_text} ({size} elements with its terminator); omit the bound and let \
                 the initializer size the array"
            )
        } else if bound + 1 == size {
            if nonstring {
                return;
            }
            format!(
                "Character array bound [{bound_text}] holds string literal {literal_text} \
                 without its terminating null character (needs {size} elements)"
            )
        } else {
            format!(
                "Character array bound [{bound_text}] is smaller than string literal \
                 {literal_text} (needs {size} elements with its terminator)"
            )
        };
        let at = site.start_position();
        out.push(RuleViolation {
            rule_id: "STR11-C".to_string(),
            severity: Severity::Low,
            message,
            file_path: String::new(),
            line: at.row + 1,
            column: at.column + 1,
            suggestion: Some(
                "Omit the array bound (use []) so the compiler sizes the array from the \
                 string literal; if the array is deliberately not a string, declare it \
                 __attribute__((nonstring))"
                    .to_string(),
            ),
            ..Default::default()
        });
    }
}

/// The name a typedef declarator defines: its innermost `type_identifier`.
fn typedef_name<'s>(d: &Node, source: &'s str) -> Option<&'s str> {
    let mut d = *d;
    while let Some(inner) = d.child_by_field_name("declarator") {
        d = inner;
    }
    (d.kind() == "type_identifier").then(|| get_node_text(&d, source))
}

fn is_string(n: &Node) -> bool {
    matches!(n.kind(), "string_literal" | "concatenated_string")
}

fn list_elements<'a>(list: &Node<'a>) -> Vec<Node<'a>> {
    let mut cursor = list.walk();
    list.named_children(&mut cursor)
        .filter(|c| c.kind() != "comment")
        .collect()
}

/// `.name` of a single-designator `initializer_pair`.
fn field_designator(pair: &Node, source: &str) -> Option<String> {
    let designators: Vec<Node> = pair
        .children_by_field_name("designator", &mut pair.walk())
        .collect();
    match designators.as_slice() {
        [d] if d.kind() == "field_designator" => {
            let id = d.named_child(0)?;
            Some(get_node_text(&id, source).to_string())
        }
        _ => None,
    }
}

/// Whether the declaration carries `__attribute__((nonstring))` or
/// `[[gnu::nonstring]]` outside its initializers.
fn has_nonstring_attribute(decl: &Node, source: &str) -> bool {
    query::find_descendants(*decl, |n| {
        matches!(
            n.kind(),
            "attribute_specifier" | "attribute_declaration" | "attribute"
        )
    })
    .iter()
    .any(|a| {
        query::find_descendants(*a, |n| n.kind() == "identifier")
            .iter()
            .any(|i| matches!(get_node_text(i, source), "nonstring" | "__nonstring__"))
    })
}

/// The element count of a string literal, terminator included: adjacent
/// literals joined, measured in the encoding its prefix selects.
fn literal_size(literal: &Node, source: &str) -> Option<i64> {
    let pieces: Vec<Node> = if literal.kind() == "concatenated_string" {
        let mut cursor = literal.walk();
        let children: Vec<Node> = literal.named_children(&mut cursor).collect();
        if children.iter().any(|c| c.kind() != "string_literal") {
            // A macro spliced between the literals: its text is unknown.
            return None;
        }
        children
    } else {
        vec![*literal]
    };
    let mut prefix = "";
    let mut bodies = Vec::new();
    for p in &pieces {
        let text = get_node_text(p, source);
        let quote = text.find('"')?;
        let (pre, rest) = text.split_at(quote);
        if !pre.is_empty() && pre != "u8" {
            if !prefix.is_empty() && prefix != "u8" && prefix != pre {
                // Differently prefixed wide literals: no portable meaning.
                return None;
            }
            prefix = pre;
        } else if pre == "u8" && prefix.is_empty() {
            prefix = "u8";
        }
        bodies.push(rest.strip_prefix('"')?.strip_suffix('"')?);
    }
    let mut count: i64 = 0;
    for body in bodies {
        count += body_elements(body, prefix)?;
    }
    Some(count + 1)
}

/// What one decoded character or escape contributes.
enum Unit {
    /// A numeric escape: exactly one element in any encoding.
    Raw,
    /// A character, encoded per the prefix.
    Char(char),
}

fn body_elements(body: &str, prefix: &str) -> Option<i64> {
    let mut units = Vec::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            units.push(Unit::Char(c));
            continue;
        }
        let e = chars.next()?;
        match e {
            '\n' => {}
            '0'..='7' => {
                for _ in 0..2 {
                    if chars.peek().is_some_and(|d| ('0'..='7').contains(d)) {
                        chars.next();
                    }
                }
                units.push(Unit::Raw);
            }
            'x' => {
                while chars.peek().is_some_and(|d| d.is_ascii_hexdigit()) {
                    chars.next();
                }
                units.push(Unit::Raw);
            }
            'u' | 'U' => {
                let n = if e == 'u' { 4 } else { 8 };
                let digits: String = (0..n).filter_map(|_| chars.next()).collect();
                let cp = u32::from_str_radix(&digits, 16).ok()?;
                units.push(Unit::Char(char::from_u32(cp)?));
            }
            _ => units.push(Unit::Raw),
        }
    }
    let mut n: i64 = 0;
    for u in units {
        n += match (u, prefix) {
            (Unit::Raw, _) => 1,
            (Unit::Char(c), "" | "u8") => c.len_utf8() as i64,
            (Unit::Char(c), "u") => c.len_utf16() as i64,
            (Unit::Char(_), "U") => 1,
            (Unit::Char(c), "L") => {
                if c.len_utf16() > 1 {
                    return None;
                }
                1
            }
            _ => return None,
        };
    }
    Some(n)
}
