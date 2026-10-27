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
//! as any other comparison (ADR-0015 Decision 7). A zero cast to an
//! arithmetic type (`(double)0`) is an exact zero. So is an object-like macro
//! that is one in every build reaching the comparison (`#define ZERO 0.0`,
//! `#define ZERO ((double)0)`): every definition in force there, the file's
//! own and those of the headers it includes before it, is one, and none of
//! those builds leaves the name to a definition the scan cannot read (a
//! `#ifndef` default a `-D` may replace). A name bound to a variable or a
//! parameter is no macro, whatever a header defines.
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
use crate::analyze::check_macros::{IncludeLine, MacroDefinition, ObjectMacroTimeline};
use crate::analyze::compile_commands::real_path;
use crate::analyze::context::{ProjectContext, VisibleTypes};
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::{get_node_text, resolve_identifier_declarator};
use crate::utility::cert_c::expr_type::{self, TypeEnv};
use crate::utility::cert_c::pp_tokens::{lex_replacement_list, PpKind, PpToken};
use lang_parsing_substrate::query;
use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
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
    /// The prescan's tables, for the macros a header defines.
    project: RefCell<Option<ProjectContext>>,
    /// The file being checked, for the headers it includes.
    file_path: RefCell<Option<PathBuf>>,
}

/// How many macros a zero is followed through (`#define ZERO ZERO_F`).
const MAX_MACRO_DEPTH: usize = 4;

/// The object-like macros a comparison can name, as written: the file's own
/// definitions in force on a line, and what the headers it includes before
/// that line leave in force, read only for a name some header defines.
struct ZeroMacros<'a> {
    own: OnceCell<ObjectMacroTimeline>,
    headers: OnceCell<Headers>,
    timelines: RefCell<HashMap<String, Rc<ObjectMacroTimeline>>>,
    source: &'a str,
    project: Option<&'a ProjectContext>,
    file_path: Option<&'a std::path::Path>,
}

/// What the file reaches through its live `#include` lines.
#[derive(Default)]
struct Headers {
    reached: Vec<Reached>,
    /// How many of the file's own `#include` lines it takes to reach a
    /// computed `#include MACRO`, whose header nothing here reads: past it,
    /// any name may have been redefined.
    computed: Option<usize>,
}

/// A header the file reaches through its live `#include` lines.
struct Reached {
    /// Its real path.
    file: String,
    /// How many of the file's own `#include` lines it takes to reach it
    /// (0 for a forced include), and to reach it through no conditional
    /// `#include` at all.
    first: usize,
    first_unconditional: Option<usize>,
}

impl ZeroMacros<'_> {
    fn own(&self) -> &ObjectMacroTimeline {
        self.own
            .get_or_init(|| ObjectMacroTimeline::of(self.source))
    }

    /// Every replacement list `name` may have on `line`, as written. `None`
    /// when some build may reach the line with a definition the scan cannot
    /// read: none of the file's own directives apply there, and no header
    /// included before the line in every build defines the name, so it is a
    /// command-line macro, a header's unknown one, or no macro at all.
    fn definitions(&self, name: &str, line: usize) -> Option<Vec<String>> {
        let in_force = self.own().in_force(name, line);
        if !in_force.inherits {
            return Some(in_force.raw);
        }
        if !self.header_defines(name) {
            return None;
        }
        let includes_before = self.own().includes().partition_point(|i| i.line < line);
        let headers = self.headers.get_or_init(|| self.reachable());
        if headers.computed.is_some_and(|n| n <= includes_before) {
            return None;
        }
        let mut raw = in_force.raw;
        let mut covered = false;
        for header in &headers.reached {
            if header.first > includes_before {
                continue;
            }
            let Some(timeline) = self.timeline(&header.file) else {
                continue;
            };
            let left = timeline.in_force(name, usize::MAX);
            // A header that is nothing but `#ifndef TOL` / `#define TOL 0.0`
            // / `#endif` reads as guarded by TOL; a `-DTOL=1e-6` build skips
            // its definition, so it proves nothing about TOL.
            covered |= header
                .first_unconditional
                .is_some_and(|n| n <= includes_before)
                && !left.inherits
                && !left.raw.is_empty()
                && timeline.include_guard() != Some(name);
            raw.extend(left.raw);
        }
        raw.sort();
        raw.dedup();
        covered.then_some(raw)
    }

    /// Whether some project header defines `name` as an object-like macro.
    fn header_defines(&self, name: &str) -> bool {
        self.project.is_some_and(|p| {
            p.macro_definitions.get(name).is_some_and(|defs| {
                defs.iter()
                    .any(|d| matches!(d, MacroDefinition::Object { .. }))
            })
        })
    }

    /// The timeline of the header at real path `file`, read once.
    fn timeline(&self, file: &str) -> Option<Rc<ObjectMacroTimeline>> {
        if let Some(timeline) = self.timelines.borrow().get(file) {
            return Some(timeline.clone());
        }
        let text = std::fs::read_to_string(file).ok()?;
        let timeline = Rc::new(ObjectMacroTimeline::of(&text));
        self.timelines
            .borrow_mut()
            .insert(file.to_string(), timeline.clone());
        Some(timeline)
    }

    /// The headers this file reaches through the prescan's include graph,
    /// following only the `#include` lines each file does not prove dead,
    /// and how many of the file's own lines it takes to reach each. With no
    /// file path nothing says which headers it sees, so none are read.
    fn reachable(&self) -> Headers {
        let (Some(project), Some(path)) = (self.project, self.file_path) else {
            return Headers::default();
        };
        let layers = [
            project.include_edges.as_ref(),
            project.include_edges_beyond_search_path.as_ref(),
        ];
        let own = real_path(path);
        let mut found: HashMap<String, Reached> = HashMap::new();
        let mut computed = None;
        // The build's forced includes come before the file's first line.
        let forced: Vec<String> = layers
            .iter()
            .filter_map(|edges| edges.get(""))
            .flatten()
            .cloned()
            .collect();
        let mut walk = Walk {
            layers: &layers,
            own: &own,
            found: &mut found,
            computed: &mut computed,
        };
        let forced = forced.into_iter().map(|f| (f, true)).collect();
        self.walk(&mut walk, forced, 0);
        for (n, include) in self.own().includes().iter().enumerate() {
            if include.computed {
                computed.get_or_insert(n + 1);
                continue;
            }
            let mut walk = Walk {
                layers: &layers,
                own: &own,
                found: &mut found,
                computed: &mut computed,
            };
            let start = targets_of(&layers, &own, include)
                .into_iter()
                .map(|(f, sure)| (f, sure && !include.conditional))
                .collect();
            self.walk(&mut walk, start, n + 1);
        }
        let mut reached: Vec<Reached> = found.into_values().collect();
        reached.sort_by(|a, b| a.file.cmp(&b.file));
        Headers { reached, computed }
    }

    /// Records each header of `start` and what it includes, through the
    /// live `#include` lines, as reached by the file's first `first` lines.
    /// Each comes with whether every build reaches it: no `#include` on the
    /// way sits in a conditional arm, and each named exactly this header.
    fn walk(&self, walk: &mut Walk, start: Vec<(String, bool)>, first: usize) {
        let Walk {
            layers,
            own,
            found,
            computed,
        } = walk;
        let mut stack = start;
        while let Some((file, unconditional)) = stack.pop() {
            if file == *own {
                continue;
            }
            // A header is walked again only when this reach is its first
            // unconditional one, so each is walked at most twice.
            let improved = match found.get_mut(&file) {
                None => {
                    found.insert(
                        file.clone(),
                        Reached {
                            file: file.clone(),
                            first,
                            first_unconditional: unconditional.then_some(first),
                        },
                    );
                    true
                }
                Some(entry) if unconditional && entry.first_unconditional.is_none() => {
                    entry.first_unconditional = Some(first);
                    true
                }
                Some(_) => false,
            };
            if !improved {
                continue;
            }
            let Some(timeline) = self.timeline(&file) else {
                continue;
            };
            for include in timeline.includes() {
                if include.computed {
                    computed.get_or_insert(first);
                    continue;
                }
                for (next, sure) in targets_of(layers, &file, include) {
                    stack.push((next, unconditional && sure && !include.conditional));
                }
            }
        }
    }
}

/// What one [`ZeroMacros::walk`] reads and fills.
struct Walk<'a, 'b> {
    layers: &'a [&'a HashMap<String, Vec<String>>],
    own: &'a str,
    found: &'b mut HashMap<String, Reached>,
    computed: &'b mut Option<usize>,
}

/// The headers the include graph may resolve `file`'s `include` to, each
/// with whether it is the one: a `"quoted"` spelling found beside `file` is,
/// as the preprocessor looks there first. Otherwise the edges whose real
/// path ends with the spelling (`.` and `..` segments dropped) are
/// candidates, and only a lone one is sure. The edges also hold `file`'s
/// `#include` lines in dead arms, so a suffix that several match proves
/// nothing.
fn targets_of(
    layers: &[&HashMap<String, Vec<String>>],
    file: &str,
    include: &IncludeLine,
) -> Vec<(String, bool)> {
    let edges: Vec<&String> = layers
        .iter()
        .filter_map(|edges| edges.get(file))
        .flatten()
        .collect();
    if include.quoted {
        if let Some(dir) = std::path::Path::new(file).parent() {
            let beside = real_path(&dir.join(&include.spelling));
            if edges.iter().any(|e| **e == beside) {
                return vec![(beside, true)];
            }
        }
    }
    let spelling = include
        .spelling
        .split(['/', '\\'])
        .filter(|segment| !matches!(*segment, "" | "." | ".."))
        .collect::<Vec<_>>()
        .join("/");
    if spelling.is_empty() {
        return Vec::new();
    }
    let mut matches: Vec<String> = edges
        .into_iter()
        .filter(|target| {
            target
                .strip_suffix(spelling.as_str())
                .is_some_and(|dir| dir.ends_with('/'))
        })
        .cloned()
        .collect();
    matches.sort();
    matches.dedup();
    let sure = matches.len() == 1;
    matches.into_iter().map(|m| (m, sure)).collect()
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

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.clone());
    }

    fn set_file_path(&self, path: &std::path::Path) {
        *self.file_path.borrow_mut() = Some(path.to_path_buf());
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        let settings = self.settings.borrow();
        let visible = self.visible.borrow();
        let env = TypeEnv::visible(&visible, settings.facts).in_tree(*root);
        let zero_exempt = settings.flag(EXACT_ZERO_OPTION);
        let project = self.project.borrow();
        let file_path = self.file_path.borrow();
        let macros = ZeroMacros {
            own: OnceCell::new(),
            headers: OnceCell::new(),
            timelines: RefCell::new(HashMap::new()),
            source,
            project: project.as_ref(),
            file_path: file_path.as_deref(),
        };
        let mut violations = Vec::new();
        self.find_fp_equality_comparisons(
            root,
            source,
            &env,
            zero_exempt.then_some(&macros),
            &mut violations,
        );
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
        zero_exempt: Option<&ZeroMacros>,
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
            if let Some(macros) = zero_exempt {
                if is_exact_zero(&left, source, macros) || is_exact_zero(&right, source, macros) {
                    continue;
                }
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
/// character constant (`'\0'`), parenthesized, signed (`-0.0`) or cast to
/// an arithmetic type (`(double)0`), or an object-like macro that is one in
/// every build ([`macro_is_zero`]).
fn is_exact_zero(node: &Node, source: &str, macros: &ZeroMacros) -> bool {
    match node.kind() {
        "parenthesized_expression" => node
            .named_child(0)
            .is_some_and(|n| is_exact_zero(&n, source, macros)),
        "unary_expression" => {
            let op = node
                .child_by_field_name("operator")
                .map(|o| get_node_text(&o, source));
            matches!(op, Some("-" | "+"))
                && node
                    .child_by_field_name("argument")
                    .is_some_and(|n| is_exact_zero(&n, source, macros))
        }
        "cast_expression" => {
            node.child_by_field_name("type")
                .is_some_and(|t| is_arithmetic_type(&t, source))
                && node
                    .child_by_field_name("value")
                    .is_some_and(|n| is_exact_zero(&n, source, macros))
        }
        "number_literal" => literal_is_zero(get_node_text(node, source)),
        "char_literal" => char_literal_is_zero(get_node_text(node, source)),
        "identifier" => {
            let name = get_node_text(node, source);
            // A name bound to a variable, a parameter or an enumerator is no
            // macro where it is used, whatever a header defines.
            resolve_identifier_declarator(node, name, source).is_none()
                && macro_is_zero(name, node.start_position().row + 1, macros, 0)
        }
        _ => false,
    }
}

/// Whether a cast's type names an arithmetic type by its keywords alone
/// (`double`, `unsigned long`): no pointer, no tag and no typedef, whose
/// meaning the cast's text does not say.
fn is_arithmetic_type(type_descriptor: &Node, source: &str) -> bool {
    type_descriptor.child_by_field_name("declarator").is_none()
        && type_descriptor
            .child_by_field_name("type")
            .is_some_and(|t| matches!(t.kind(), "primitive_type" | "sized_type_specifier"))
        && get_node_text(type_descriptor, source)
            .split_whitespace()
            .all(|word| ARITHMETIC_KEYWORDS.contains(&word) || QUALIFIERS.contains(&word))
}

/// The keywords of an arithmetic type specifier (C11 6.7.2).
const ARITHMETIC_KEYWORDS: &[&str] = &[
    "char", "short", "int", "long", "float", "double", "signed", "unsigned", "bool", "_Complex",
];

/// The type qualifiers a cast may carry.
const QUALIFIERS: &[&str] = &["const", "volatile"];

/// Whether the object-like macro `name` is an exact zero on `line` in every
/// build: every build has a definition the scan can read there
/// ([`ZeroMacros::definitions`]), and each is a zero.
fn macro_is_zero(name: &str, line: usize, macros: &ZeroMacros, depth: usize) -> bool {
    if depth >= MAX_MACRO_DEPTH {
        return false;
    }
    let Some(definitions) = macros.definitions(name, line) else {
        return false;
    };
    !definitions.is_empty()
        && definitions.iter().all(|body| {
            let tokens = lex_replacement_list(body, false);
            tokens_are_zero(&tokens, line, macros, depth + 1)
        })
}

/// Whether a replacement list is a zero constant: a zero literal, the null
/// character, or a zero macro, under parentheses, a cast to an arithmetic
/// type (`(double)0`) and a sign.
fn tokens_are_zero(tokens: &[PpToken], line: usize, macros: &ZeroMacros, depth: usize) -> bool {
    match tokens {
        [] => false,
        [only] => match only.kind {
            PpKind::Number => literal_is_zero(&only.text),
            PpKind::CharLiteral => char_literal_is_zero(&only.text),
            PpKind::Identifier => macro_is_zero(&only.text, line, macros, depth),
            _ => false,
        },
        [sign, rest @ ..] if sign.is("-") || sign.is("+") => {
            tokens_are_zero(rest, line, macros, depth)
        }
        [open, ..] if open.is("(") => {
            let Some(close) = matching_paren(tokens) else {
                return false;
            };
            let inner = &tokens[1..close];
            let rest = &tokens[close + 1..];
            if rest.is_empty() {
                tokens_are_zero(inner, line, macros, depth)
            } else {
                // A cast to an arithmetic type, named by its keywords.
                inner
                    .iter()
                    .any(|t| ARITHMETIC_KEYWORDS.contains(&&*t.text))
                    && inner.iter().all(|t| {
                        ARITHMETIC_KEYWORDS.contains(&&*t.text) || QUALIFIERS.contains(&&*t.text)
                    })
                    && tokens_are_zero(rest, line, macros, depth)
            }
        }
        _ => false,
    }
}

/// The index of the `)` closing the `(` at `tokens[0]`.
fn matching_paren(tokens: &[PpToken]) -> Option<usize> {
    let mut depth = 0usize;
    for (i, t) in tokens.iter().enumerate() {
        if t.is("(") {
            depth += 1;
        } else if t.is(")") {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
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
