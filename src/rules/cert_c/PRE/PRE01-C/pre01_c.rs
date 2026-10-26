// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! PRE01-C: Use parentheses within macros around parameter names
//!
//! This rule addresses operator precedence issues in macro expansions.
//! Without parentheses around each parameter reference, complex expressions
//! passed as arguments can cause unexpected behavior due to operator precedence.
//!
//! ## Non-compliant example:
//!
//! ```c
//! #define CUBE(I) (I * I * I)
//! int result = 81 / CUBE(2 + 1);  // Expands to 81 / (2 + 1 * 2 + 1 * 2 + 1) = 11 (wrong!)
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! #define CUBE(I) ( (I) * (I) * (I) )
//! int result = 81 / CUBE(2 + 1);  // Expands to 81 / ( (2 + 1) * (2 + 1) * (2 + 1) ) = 3 (correct!)
//! ```
//!
//! ## Exceptions:
//!
//! 1. **Function call arguments**: Parameters already in comma-separated lists don't need parentheses:
//!    ```c
//!    #define FOO(a, b) bar(a, b)  // OK - commas have lower precedence
//!    ```
//!
//! 2. **Token concatenation (##) and stringification (#)**: These operators require un-parenthesized identifiers:
//!    ```c
//!    #define JOIN(a, b) (a ## b)  // OK - ## requires raw identifier
//!    #define SHOW(a) printf(#a " = %d\n", a)  // OK - # requires raw identifier
//!    ```
//!
//! 3. **String-literal concatenation**: a use next to a string literal takes
//!    a literal argument, and `(a) "\n"` does not compile:
//!    ```c
//!    #define PUTLINE(a) puts(a "\n")  // OK
//!    ```
//!
//! 4. **Directly followed by an identifier, or a cast's whole type name**:
//!    a type name (`T n`, `qual size_t n`, `(T *)0`, `(const T *)0`,
//!    `sizeof(T **)`) or a macro every definition of which expands to string
//!    literals cannot take parentheses. An operand followed by an operator
//!    (`a op b`, or `x MOD 3` with `MOD` a macro for `%`) or by a keyword
//!    (`x else`) stays reported, as does `T * x`, a declaration or a
//!    multiplication depending on the argument:
//!    ```c
//!    #define DECLARE(T) T count = 0      // OK
//!    #define NULL_OF(T) ((T *)0)         // OK
//!    ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::check_macros::{collect_macro_definitions, MacroDefinition};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::utility::cert_c::expr_type::is_standard_typedef_name;
use crate::utility::cert_c::pp_tokens::{
    define_at, lex_replacement_list, matching_close, LineIndex, PpKind, PpToken, KEYWORDS,
};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

/// Keywords that make the token before them part of a type name: the
/// type specifiers and qualifiers (`T const`, `qual int`).
const TYPE_WORDS: &[&str] = &[
    "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool",
    "_Complex", "const", "volatile", "restrict", "_Atomic", "struct", "union", "enum",
];

/// Deepest chain of macros [`Names::shape`] follows before it answers
/// [`Shape::Unknown`], so a long chain cannot exhaust the stack.
const MAX_MACRO_DEPTH: usize = 64;

/// What the names after a parameter use may be, for one file: the macros
/// and typedefs of the scanned files (the prescan) and of this file.
struct Names<'a> {
    project_macros: &'a HashMap<String, Vec<MacroDefinition>>,
    file_macros: &'a HashMap<String, Vec<MacroDefinition>>,
    project_typedefs: &'a HashMap<String, String>,
    file_typedefs: &'a HashSet<String>,
    /// [`Names::shape`] per macro name, once for the file. A name being
    /// expanded is filed [`Shape::Unknown`] until it is done, so a macro
    /// that reaches itself (`#define A B` and `#define B A`) is not
    /// expanded again: the preprocessor leaves such a name unexpanded.
    shapes: RefCell<HashMap<String, Shape>>,
}

impl Names<'_> {
    /// Every distinct definition of `name`: a file's own macros are in the
    /// project tables too, and each definition is read once.
    fn macro_definitions(&self, name: &str) -> Vec<&MacroDefinition> {
        let mut defs: Vec<&MacroDefinition> = Vec::new();
        for def in [self.project_macros.get(name), self.file_macros.get(name)]
            .into_iter()
            .flatten()
            .flatten()
        {
            if !defs.contains(&def) {
                defs.push(def);
            }
        }
        defs
    }

    /// A type keyword or qualifier, a typedef the scan sees, or a typedef
    /// name the standard library declares (`size_t`, `uint32_t`), whose
    /// header the scan may not read.
    fn is_type(&self, name: &str) -> bool {
        TYPE_WORDS.contains(&name)
            || self.project_typedefs.contains_key(name)
            || self.file_typedefs.contains(name)
            || is_standard_typedef_name(name)
    }

    /// What `name` expands to, by every definition the scan sees.
    /// [`Shape::Strings`]: string literals only, directly, through its own
    /// parameters, or through macros or invocations that expand to them
    /// (`#define FMT_U64 "%" PRIu64`; valkey's `COMPACT_FMT_2(fmt, value)`,
    /// which is `fmt`). [`Shape::Other`]: some definition holds an operator,
    /// a number or anything else, as an operator macro (`#define MOD %`)
    /// does. [`Shape::Unknown`]: not a macro the scan sees, a definition the
    /// macro tables cannot read (variadic, `##`), one that reaches itself,
    /// or one nested deeper than [`MAX_MACRO_DEPTH`].
    fn shape(&self, name: &str, depth: usize) -> Shape {
        if let Some(&known) = self.shapes.borrow().get(name) {
            return known;
        }
        let defs = self.macro_definitions(name);
        if defs.is_empty() || depth >= MAX_MACRO_DEPTH {
            return Shape::Unknown;
        }
        self.shapes
            .borrow_mut()
            .insert(name.to_string(), Shape::Unknown);
        let shape = defs
            .iter()
            .map(|def| match def {
                MacroDefinition::Object { body } => self.body_shape(name, body, &[], depth),
                MacroDefinition::Function { params, body } => {
                    self.body_shape(name, body, params, depth)
                }
                MacroDefinition::Opaque => Shape::Unknown,
            })
            .fold(Shape::Strings, Shape::and);
        self.shapes.borrow_mut().insert(name.to_string(), shape);
        shape
    }

    fn body_shape(&self, name: &str, body: &str, params: &[String], depth: usize) -> Shape {
        let tokens = lex_replacement_list(body, !params.is_empty());
        if tokens.is_empty() {
            return Shape::Unknown;
        }
        let mut shape = Shape::Strings;
        let mut i = 0;
        while i < tokens.len() {
            let t = &tokens[i];
            match t.kind {
                PpKind::StringLiteral => {}
                PpKind::Identifier
                    if t.text == "__VA_ARGS__" || params.contains(&t.text.to_string()) => {}
                PpKind::Identifier if t.text != name => {
                    shape = shape.and(self.shape(&t.text, depth + 1));
                    // An invocation's arguments are its own.
                    if tokens.get(i + 1).is_some_and(|n| n.is("(")) {
                        match matching_close(&tokens, i + 1) {
                            Some(close) => i = close,
                            None => return Shape::Other,
                        }
                    }
                }
                _ => return Shape::Other,
            }
            if shape == Shape::Other {
                return shape;
            }
            i += 1;
        }
        shape
    }
}

/// What a macro expands to ([`Names::shape`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    Strings,
    Other,
    Unknown,
}

impl Shape {
    /// Both at once: anything else wins, then not knowing.
    fn and(self, other: Shape) -> Shape {
        match (self, other) {
            (Shape::Other, _) | (_, Shape::Other) => Shape::Other,
            (Shape::Unknown, _) | (_, Shape::Unknown) => Shape::Unknown,
            _ => Shape::Strings,
        }
    }
}

pub struct Pre01C {
    /// Every definition of every macro name across the scanned files.
    macro_definitions: RefCell<Arc<HashMap<String, Vec<MacroDefinition>>>>,
    /// The scanned files' typedef names.
    typedef_types: RefCell<Arc<HashMap<String, String>>>,
}

impl Pre01C {
    pub fn new() -> Self {
        Self {
            macro_definitions: RefCell::new(Arc::new(HashMap::new())),
            typedef_types: RefCell::new(Arc::new(HashMap::new())),
        }
    }

    /// Whether the parameter use at `k` needs no parentheses: it is already
    /// parenthesized, or it is followed by `,` or `)` inside some `(` (a
    /// function-call argument; commas have the lowest precedence), or it sits
    /// where parentheses would not compile: in a string concatenation or a
    /// type position.
    fn is_exempt_position(tokens: &[PpToken], k: usize, params: &[&str], names: &Names) -> bool {
        let prev = k.checked_sub(1).map(|p| &tokens[p]);
        let next = tokens.get(k + 1);
        let closes = next.is_some_and(|t| t.is(")"));
        if prev.is_some_and(|t| t.is("(")) && closes {
            return true;
        }
        let mut depth = 0usize;
        let inside_parens = tokens[..k].iter().rev().any(|t| {
            if t.is(")") {
                depth += 1;
            } else if t.is("(") {
                if depth == 0 {
                    return true;
                }
                depth -= 1;
            }
            false
        });
        (inside_parens && (closes || next.is_some_and(|t| t.is(","))))
            || Self::is_concatenated_with_literal(tokens, k)
            || Self::is_type_position(tokens, k, params, names)
    }

    /// Whether the use at `k` is next to a string literal: `puts(a "\n")`
    /// pastes the argument into a string concatenation, and `(a) "\n"`, the
    /// parenthesized form, does not compile. Only a literal argument can
    /// make sense there, and a literal has no precedence to protect.
    fn is_concatenated_with_literal(tokens: &[PpToken], k: usize) -> bool {
        let is_string = |t: &PpToken| t.kind == PpKind::StringLiteral;
        k.checked_sub(1).is_some_and(|p| is_string(&tokens[p]))
            || tokens.get(k + 1).is_some_and(is_string)
    }

    /// Whether the use at `k` sits where parentheses may not compile: in a
    /// type name, or before a macro that expands to string literals. That is
    /// a use directly followed by an identifier that is a type keyword or a
    /// typedef (`qual int`, `T const`), by a macro every definition of which
    /// expands to string literals (`fmt PRIu64`), or by a declarator (`T n`,
    /// `type name = 0`); or the whole of a cast's type name up to its pointer
    /// declarators, qualifiers included (`(T *)0`, `(const T *)0`,
    /// `sizeof(T **)`). A following name that is another macro is an
    /// operator (`x MOD 3`), and one followed by an operand (a number, a
    /// character constant or another parameter: `a op b`, `x MOD 3` with
    /// `MOD` defined nowhere the scan sees) is too, so the use is an operand
    /// and stays reported. A use between an operand and an operand is the
    /// operator itself (`op` in lua's `l_castS2U(v1) op l_castS2U(v2)`, and
    /// in `a op b`), which parentheses would break. `T * x` is a declaration
    /// or a multiplication, and stays reported. So does `qual` in
    /// `qual T name` when `T` is a name the scan cannot tell is a type: it
    /// reads exactly as `a op b`, and the ambiguity is accepted rather than
    /// exempting every operand before an unknown name and a parameter.
    fn is_type_position(tokens: &[PpToken], k: usize, params: &[&str], names: &Names) -> bool {
        let is_param =
            |t: &PpToken| t.kind == PpKind::Identifier && params.contains(&t.text.as_ref());
        let ends_operand = k.checked_sub(1).is_some_and(|p| {
            let t = &tokens[p];
            t.is(")") || t.is("]") || t.is_literal() || t.kind == PpKind::Number || is_param(t)
        });
        // A keyword (`else`) starts no operand.
        let starts_operand = |t: &PpToken| {
            t.is("(")
                || t.is_literal()
                || t.kind == PpKind::Number
                || (t.kind == PpKind::Identifier && !KEYWORDS.contains(&t.text.as_ref()))
        };
        if ends_operand && tokens.get(k + 1).is_some_and(starts_operand) {
            return true;
        }
        if let Some(next) = tokens.get(k + 1).filter(|t| t.kind == PpKind::Identifier) {
            if names.is_type(&next.text) {
                return true;
            }
            // Any other keyword (`x else`) follows a statement or an
            // operand, never a type name.
            if KEYWORDS.contains(&next.text.as_ref()) {
                return false;
            }
            match names.shape(&next.text, 0) {
                Shape::Strings => return true,
                Shape::Other => return false,
                Shape::Unknown => {}
            }
            let operand_after = tokens.get(k + 2).is_some_and(|t| {
                matches!(t.kind, PpKind::Number | PpKind::CharLiteral) || is_param(t)
            });
            return !operand_after;
        }
        // Back over the qualifiers and tag keywords before it to the `(`.
        let open = tokens[..k].iter().rposition(|t| {
            !(t.kind == PpKind::Identifier && TYPE_WORDS.contains(&t.text.as_ref()))
        });
        if !open.is_some_and(|p| tokens[p].is("(")) {
            return false;
        }
        let stars = tokens[k + 1..].iter().take_while(|t| t.is("*")).count();
        stars > 0 && tokens.get(k + 1 + stars).is_some_and(|t| t.is(")"))
    }

    /// The names this file's typedefs declare, in any arm.
    fn file_typedef_names(root: &Node, source: &str) -> HashSet<String> {
        let mut names = HashSet::new();
        for def in query::find_descendants_of_kind(*root, "type_definition") {
            let mut cursor = def.walk();
            for declarator in def.children_by_field_name("declarator", &mut cursor) {
                if let Some(name) = std::iter::once(declarator)
                    .chain(query::find_descendants_of_kind(
                        declarator,
                        "type_identifier",
                    ))
                    .find(|n| n.kind() == "type_identifier")
                {
                    if let Ok(text) = name.utf8_text(source.as_bytes()) {
                        names.insert(text.to_string());
                    }
                }
            }
        }
        names
    }

    /// Check a function-like macro definition for unparenthesized parameters
    fn check_function_macro(
        &self,
        node: &Node,
        source: &str,
        lines: &LineIndex,
        names: &Names,
        violations: &mut Vec<RuleViolation>,
    ) {
        // The directive's own text, not tree-sitter's fields: a comment in a
        // function-like macro's body can make it misparse the directive.
        let Some(define) = define_at(node, source) else {
            return;
        };
        let Some(params) = &define.params else {
            return;
        };
        let tokens = define.tokens();
        let param_names: Vec<&str> = params.iter().map(String::as_str).collect();

        // Every use of each parameter in the replacement list, each reported
        // where it is written. A spelling in a string or character literal
        // or a comment is not a use, and the operand of `#` or `##` must stay
        // a bare identifier.
        for param in params.iter().filter(|p| !p.ends_with("...")) {
            for (k, token) in tokens.iter().enumerate() {
                if !token.is_plain_use_of(param)
                    || Self::is_exempt_position(&tokens, k, &param_names, names)
                {
                    continue;
                }
                let at = lines.point(define.body_start + token.start);
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Macro parameter '{}' of '{}' is not parenthesized in replacement text. This can cause operator precedence issues.",
                        param, define.name
                    ),
                    file_path: String::new(),
                    line: at.row + 1,
                    column: at.column + 1,
                    suggestion: Some(format!(
                        "Wrap parameter '{}' in parentheses: ({}) instead of {}",
                        param, param, param
                    )),
                    ..Default::default()
                });
            }
        }
    }
}

impl CertRule for Pre01C {
    fn rule_id(&self) -> &'static str {
        "PRE01-C"
    }

    fn description(&self) -> &'static str {
        "Use parentheses within macros around parameter names"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "PRE01-C"
    }

    /// A name after a parameter use is told apart by the macros and typedefs
    /// that define it, which a header may supply.
    fn reads_header_facts(&self) -> bool {
        true
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let macros =
            query::find_descendants_of_kinds(*node, &["preproc_function_def", "preproc_def"]);
        if macros.is_empty() {
            return violations;
        }
        let lines = LineIndex::new(source);
        let project_macros = self.macro_definitions.borrow();
        let project_typedefs = self.typedef_types.borrow();
        let file_macros = collect_macro_definitions(source);
        let file_typedefs = Self::file_typedef_names(node, source);
        let names = Names {
            project_macros: &project_macros,
            file_macros: &file_macros,
            project_typedefs: &project_typedefs,
            file_typedefs: &file_typedefs,
            shapes: RefCell::default(),
        };
        for macro_node in macros {
            self.check_function_macro(&macro_node, source, &lines, &names, &mut violations);
        }
        violations
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.macro_definitions.borrow_mut() = context.macro_definitions.clone();
        *self.typedef_types.borrow_mut() = context.typedef_types.clone();
    }
}
