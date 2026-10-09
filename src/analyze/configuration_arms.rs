//! Which lines of a file the build configuration compiles
//! (`docs/design/generated-headers-and-configuration.md` §4.2, M2).
//!
//! A file the configuration compiles still holds arms it does not:
//! `#ifdef CONFIG_VTX` in a build without VT-x, the whole body of an
//! SMP-only file in a uniprocessor build. A build-generated header's facts
//! describe the configuration, so they apply to the arms it compiles and to
//! nothing else. This module decides, line by line, which arms those are:
//! the configuration's macro state is the database's `-D`/`-U`, the
//! definitions in its generated headers, and the definitions the project's
//! own headers derive from those (`#ifdef CONFIG_ENABLE_SMP_SUPPORT` /
//! `#define ENABLE_SMP_SUPPORT`), and a name none of them defines is
//! undefined, as it is for the compiler. Only an identifier reserved to the
//! implementation (`__GNUC__`, `_WIN32`), which the compiler may predefine,
//! is unknown unless the database defines it.
//!
//! A line is *compiled* when every arm enclosing it is taken under that
//! state, *excluded* when one is not, and *unknown* when the state cannot
//! decide (a reserved name, a function-like macro in a condition, a value
//! that is not an integer). Only a compiled line sees generated facts; an
//! unknown one is treated as excluded, the conservative choice, as if the
//! headers were missing. This decides which facts a line resolves names
//! with, never whether a finding is emitted (ADR-0010 D3).

use std::collections::HashMap;
use std::path::Path;

use super::compile_commands::CompileDb;

/// A three-valued preprocessor value: a known integer, or unknown.
type Val = Option<i64>;

/// The configuration's macro state: every name it defines, with its integer
/// value when it has one. A name absent from it is undefined.
#[derive(Debug, Clone, Default)]
pub struct ConfigState {
    defined: HashMap<String, Option<i64>>,
}

impl ConfigState {
    /// The state of `db`'s configuration: its `-D` flags, then the
    /// definitions in `generated` headers and in `headers` (the project
    /// headers the configuration's files reach), each read under the state
    /// so far until nothing new is defined. Include guards are taken as
    /// open, as on a header's first inclusion.
    pub fn build<'a>(
        db: Option<&CompileDb>,
        generated: impl IntoIterator<Item = &'a Path>,
        headers: impl IntoIterator<Item = &'a Path>,
    ) -> Self {
        let mut state = ConfigState::default();
        if let Some(db) = db {
            for d in &db.defines {
                // A bare -DFOO defines FOO as 1.
                let value = if d.body.trim().is_empty() {
                    Some(1)
                } else {
                    int_value(&d.body)
                };
                state.defined.insert(d.name().to_string(), value);
            }
        }
        let texts: Vec<String> = generated
            .into_iter()
            .chain(headers)
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .collect();
        // Monotone in practice: each round can only add names; a bound keeps
        // a header whose arms flip on its own definitions from looping.
        for _ in 0..8 {
            let before = state.defined.len();
            for text in &texts {
                let found = scan(text, &state, true).defines;
                for (name, value) in found {
                    state.defined.entry(name).or_insert(value);
                }
            }
            if state.defined.len() == before {
                break;
            }
        }
        state
    }

    fn value_of(&self, name: &str) -> Lookup {
        match self.defined.get(name) {
            Some(v) => Lookup::Defined(*v),
            None if is_reserved(name) => Lookup::Unknown,
            None => Lookup::Undefined,
        }
    }
}

/// The state as a file sees it from a given line: the configuration's,
/// with the file's own `#define`s and `#undef`s so far on top, kept apart so
/// that reading a header never copies the whole state.
struct View<'a> {
    base: &'a ConfigState,
    /// Name -> `Some(value)` defined here, `None` undefined here.
    local: HashMap<String, Option<Option<i64>>>,
}

impl View<'_> {
    fn value_of(&self, name: &str) -> Lookup {
        match self.local.get(name) {
            Some(Some(v)) => Lookup::Defined(*v),
            Some(None) => Lookup::Undefined,
            None => self.base.value_of(name),
        }
    }
}

enum Lookup {
    Defined(Option<i64>),
    Undefined,
    Unknown,
}

/// Whether every line of `source` the configuration compiles is told apart:
/// `true` at a line every enclosing arm of which is taken under `state`,
/// `false` at one the configuration excludes or cannot decide. Indexed from
/// 1; index 0 is unused. A file's own `#define`s count from where they are.
pub fn compiled_lines(source: &str, state: &ConfigState) -> Vec<bool> {
    scan(source, state, false).compiled
}

/// Whether `compiled` excludes any line holding code (not a directive, a
/// comment or blank) that names one of `names`, or a name the file itself
/// spells on a line together with one of them (`int nodes[MAX_NODES];`
/// makes `nodes` depend on the generated `MAX_NODES`): a line where the two
/// contexts could resolve a name differently. One hop, within the file; a
/// name a project header derives from a generated one is not followed.
pub fn excludes_code_naming(
    source: &str,
    compiled: &[bool],
    names: &std::collections::HashSet<String>,
) -> bool {
    let mut in_comment = false;
    let lines: Vec<String> = source
        .lines()
        .map(|l| strip_comments(l, &mut in_comment))
        .collect();
    let mut dependent: std::collections::HashSet<&str> = std::collections::HashSet::new();
    // Code only: a configuration test such as `#ifdef HAVE_X` names the
    // generated macro but makes nothing else depend on it.
    for line in lines.iter().filter(|l| !l.trim_start().starts_with('#')) {
        if identifiers(line).any(|id| names.contains(id)) {
            dependent.extend(identifiers(line).filter(|id| !is_keyword(id)));
        }
    }
    for (i, code) in lines.iter().enumerate() {
        let trimmed = code.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if compiled.get(i + 1).copied().unwrap_or(true) {
            continue;
        }
        if identifiers(trimmed).any(|id| names.contains(id) || dependent.contains(id)) {
            return true;
        }
    }
    false
}

fn is_keyword(id: &str) -> bool {
    matches!(
        id,
        "auto"
            | "break"
            | "case"
            | "char"
            | "const"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extern"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "register"
            | "restrict"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "struct"
            | "switch"
            | "typedef"
            | "union"
            | "unsigned"
            | "void"
            | "volatile"
            | "while"
            | "_Bool"
            | "define"
            | "include"
    )
}

/// Every name a header defines at file scope: `#define`d macros, and the
/// identifiers declared or defined at the start of a top-level declaration
/// (functions, typedefs, objects). Over-collecting only costs a second
/// analysis of a file; under-collecting would leave generated facts in an
/// excluded arm.
pub fn names_defined_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_comment = false;
    for line in text.lines() {
        let code = strip_comments(line, &mut in_comment);
        let t = code.trim();
        if let Some(rest) = t.strip_prefix('#') {
            let rest = rest.trim_start();
            if let Some(def) = rest.strip_prefix("define") {
                if let Some(name) = identifiers(def).next() {
                    out.push(name.to_string());
                }
            }
            continue;
        }
        // `type name(` and `} name;` / `typedef ... name;` shapes.
        if let Some(open) = t.find('(') {
            if let Some(name) = identifiers(&t[..open]).last() {
                out.push(name.to_string());
            }
        }
        if t.ends_with(';') {
            if let Some(name) = identifiers(t.trim_end_matches(';')).last() {
                out.push(name.to_string());
            }
        }
    }
    out
}

struct Scan {
    compiled: Vec<bool>,
    defines: Vec<(String, Option<i64>)>,
}

/// One frame of the conditional stack.
struct Frame {
    /// The arm currently open is taken (`Some(true)`), not (`Some(false)`),
    /// or unknown.
    current: Option<bool>,
    /// Some earlier arm of this conditional was taken, as far as known.
    any_taken: Option<bool>,
}

fn scan(source: &str, state: &ConfigState, guards_open: bool) -> Scan {
    let lines: Vec<&str> = source.lines().collect();
    let mut compiled = vec![true; lines.len() + 1];
    let mut defines = Vec::new();
    let mut local = View {
        base: state,
        local: HashMap::new(),
    };
    let mut stack: Vec<Frame> = Vec::new();
    let guard = if guards_open {
        include_guard(&lines)
    } else {
        None
    };
    let mut in_comment = false;
    let mut i = 0;
    while i < lines.len() {
        // A directive may continue over `\`-ended lines.
        let start = i;
        let mut logical = strip_comments(lines[i], &mut in_comment);
        while logical.trim_end().ends_with('\\') && i + 1 < lines.len() {
            logical = logical.trim_end().trim_end_matches('\\').to_string();
            i += 1;
            logical.push(' ');
            logical.push_str(&strip_comments(lines[i], &mut in_comment));
        }
        let effective = effective(&stack);
        for n in start..=i {
            compiled[n + 1] = effective == Some(true);
        }
        i += 1;
        let t = logical.trim();
        let Some(directive) = t.strip_prefix('#') else {
            continue;
        };
        let directive = directive.trim_start();
        let (word, rest) = split_word(directive);
        match word {
            "ifdef" | "ifndef" => {
                let name = identifiers(rest).next().unwrap_or("");
                let is_guard =
                    word == "ifndef" && guard.as_deref() == Some(name) && stack.is_empty();
                let defined = match local.value_of(name) {
                    Lookup::Defined(_) => Some(true),
                    Lookup::Undefined => Some(false),
                    Lookup::Unknown => None,
                };
                let cond = if is_guard {
                    Some(true)
                } else if word == "ifdef" {
                    defined
                } else {
                    defined.map(|d| !d)
                };
                stack.push(Frame {
                    current: cond,
                    any_taken: cond,
                });
            }
            "if" => {
                let cond = eval(rest, &local).map(|v| v != 0);
                stack.push(Frame {
                    current: cond,
                    any_taken: cond,
                });
            }
            "elif" | "elifdef" | "elifndef" => {
                if let Some(top) = stack.last_mut() {
                    let cond = match word {
                        "elif" => eval(rest, &local).map(|v| v != 0),
                        _ => {
                            let name = identifiers(rest).next().unwrap_or("");
                            let d = match local.value_of(name) {
                                Lookup::Defined(_) => Some(true),
                                Lookup::Undefined => Some(false),
                                Lookup::Unknown => None,
                            };
                            if word == "elifdef" {
                                d
                            } else {
                                d.map(|d| !d)
                            }
                        }
                    };
                    top.current = and(not(top.any_taken), cond);
                    top.any_taken = or(top.any_taken, cond);
                }
            }
            "else" => {
                if let Some(top) = stack.last_mut() {
                    top.current = not(top.any_taken);
                    top.any_taken = Some(true);
                }
            }
            "endif" => {
                stack.pop();
            }
            "define" if effective == Some(true) => {
                let (name, body) = split_define(rest);
                if !name.is_empty() && guard.as_deref() != Some(name.as_str()) {
                    let value = if body.starts_with('(')
                        && rest.trim_start().starts_with(&format!("{name}("))
                    {
                        None
                    } else {
                        int_value(&body)
                    };
                    local.local.insert(name.clone(), Some(value));
                    defines.push((name, value));
                }
            }
            "undef" if effective == Some(true) => {
                if let Some(name) = identifiers(rest).next() {
                    local.local.insert(name.to_string(), None);
                }
            }
            _ => {}
        }
    }
    Scan { compiled, defines }
}

/// Whether the arms on the stack are all taken: `Some(true)`, one is not:
/// `Some(false)`, or that cannot be decided.
fn effective(stack: &[Frame]) -> Option<bool> {
    let mut out = Some(true);
    for f in stack {
        out = and(out, f.current);
    }
    out
}

fn and(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (Some(false), _) | (_, Some(false)) => Some(false),
        (Some(true), Some(true)) => Some(true),
        _ => None,
    }
}

fn or(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        _ => None,
    }
}

fn not(a: Option<bool>) -> Option<bool> {
    a.map(|b| !b)
}

/// The macro a header's include guard tests: its first directive is
/// `#ifndef G` and its second `#define G`.
fn include_guard(lines: &[&str]) -> Option<String> {
    let mut in_comment = false;
    let mut directives = lines.iter().filter_map(|l| {
        let code = strip_comments(l, &mut in_comment);
        let t = code.trim().to_string();
        t.strip_prefix('#').map(|d| d.trim_start().to_string())
    });
    let first = directives.next()?;
    let (w1, r1) = split_word(&first);
    if w1 != "ifndef" {
        return None;
    }
    let name = identifiers(r1).next()?.to_string();
    let second = directives.next()?;
    let (w2, r2) = split_word(&second);
    (w2 == "define" && identifiers(r2).next() == Some(name.as_str())).then_some(name)
}

/// Implementation-reserved: `__x` or `_X` (C11 7.1.3).
fn is_reserved(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next() == Some('_')
        && chars
            .next()
            .is_some_and(|c| c == '_' || c.is_ascii_uppercase())
}

fn split_word(s: &str) -> (&str, &str) {
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    (&s[..end], &s[end..])
}

fn split_define(rest: &str) -> (String, String) {
    let rest = rest.trim_start();
    let (name, body) = split_word(rest);
    (name.to_string(), body.trim().to_string())
}

/// The value of a macro body that is an integer literal (or a parenthesised
/// one), else `None`.
fn int_value(body: &str) -> Option<i64> {
    let mut b = body.trim();
    while let Some(inner) = b.strip_prefix('(').and_then(|r| r.strip_suffix(')')) {
        b = inner.trim();
    }
    if b.is_empty() {
        return None;
    }
    parse_int(b)
}

fn parse_int(tok: &str) -> Option<i64> {
    let t = tok.trim_end_matches(['u', 'U', 'l', 'L']);
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()
    } else if t.len() > 1 && t.starts_with('0') && t.bytes().all(|b| b.is_ascii_digit()) {
        i64::from_str_radix(&t[1..], 8).ok()
    } else {
        t.parse().ok()
    }
}

/// `line` with `/* */` and `//` comments removed, carrying an open block
/// comment over to the next line.
fn strip_comments(line: &str, in_comment: &mut bool) -> String {
    let mut out = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if *in_comment {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                *in_comment = false;
            }
            continue;
        }
        match (c, chars.peek()) {
            ('/', Some('*')) => {
                chars.next();
                *in_comment = true;
                out.push(' ');
            }
            ('/', Some('/')) => break,
            _ => out.push(c),
        }
    }
    out
}

fn identifiers(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| w.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
}

// ── #if expression evaluation, three-valued ────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(i64),
    Ident(String),
    Op(&'static str),
}

fn tokenize(s: &str) -> Option<Vec<Tok>> {
    const OPS: [&str; 22] = [
        "&&", "||", "==", "!=", "<=", ">=", "<<", ">>", "(", ")", "!", "~", "*", "/", "%", "+",
        "-", "<", ">", "&", "|", "^",
    ];
    let mut out = Vec::new();
    let mut rest = s.trim();
    while !rest.is_empty() {
        let c = rest.chars().next().unwrap();
        if c.is_whitespace() {
            rest = rest.trim_start();
            continue;
        }
        if c.is_ascii_digit() {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric()))
                .unwrap_or(rest.len());
            out.push(Tok::Num(parse_int(&rest[..end])?));
            rest = &rest[end..];
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let (w, r) = split_word(rest);
            out.push(Tok::Ident(w.to_string()));
            rest = r;
            continue;
        }
        let op = OPS.iter().find(|op| rest.starts_with(**op))?;
        out.push(Tok::Op(op));
        rest = &rest[op.len()..];
    }
    Some(out)
}

/// The value of a `#if` condition under `state`, or `None` when it cannot be
/// decided.
fn eval(expr: &str, state: &View) -> Val {
    let toks = tokenize(expr)?;
    let mut p = Parser {
        toks: &toks,
        pos: 0,
        state,
    };
    let v = p.expr(0)?;
    (p.pos == toks.len()).then_some(())?;
    v
}

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
    state: &'a View<'a>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn bump(&mut self) -> Option<&Tok> {
        let t = self.toks.get(self.pos);
        self.pos += 1;
        t
    }

    fn eat(&mut self, op: &str) -> bool {
        if self.peek() == Some(&Tok::Op(op_static(op))) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Precedence climbing. The outer `Option` fails the parse; the inner
    /// one is the three-valued result.
    fn expr(&mut self, min_prec: u8) -> Option<Val> {
        let mut lhs = self.unary()?;
        while let Some(Tok::Op(op)) = self.peek() {
            let op = *op;
            let Some(prec) = binary_prec(op) else {
                break;
            };
            if prec < min_prec {
                break;
            }
            self.pos += 1;
            let rhs = self.expr(prec + 1)?;
            lhs = apply(op, lhs, rhs);
        }
        Some(lhs)
    }

    fn unary(&mut self) -> Option<Val> {
        if self.eat("!") {
            return Some(self.unary()?.map(|v| (v == 0) as i64));
        }
        if self.eat("-") {
            return Some(self.unary()?.map(|v| v.wrapping_neg()));
        }
        if self.eat("+") {
            return self.unary();
        }
        if self.eat("~") {
            return Some(self.unary()?.map(|v| !v));
        }
        if self.eat("(") {
            let v = self.expr(0)?;
            self.eat(")").then_some(())?;
            return Some(v);
        }
        match self.bump()?.clone() {
            Tok::Num(n) => Some(Some(n)),
            Tok::Ident(name) if name == "defined" => {
                let paren = self.eat("(");
                let Some(Tok::Ident(target)) = self.bump().cloned() else {
                    return None;
                };
                if paren {
                    self.eat(")").then_some(())?;
                }
                Some(match self.state.value_of(&target) {
                    Lookup::Defined(_) => Some(1),
                    Lookup::Undefined => Some(0),
                    Lookup::Unknown => None,
                })
            }
            Tok::Ident(name) => {
                // A function-like macro call: its expansion is not known here.
                if self.peek() == Some(&Tok::Op("(")) {
                    let mut depth = 0;
                    while let Some(t) = self.bump() {
                        match t {
                            Tok::Op("(") => depth += 1,
                            Tok::Op(")") => {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    return Some(None);
                }
                Some(match self.state.value_of(&name) {
                    Lookup::Defined(v) => v,
                    Lookup::Undefined => Some(0),
                    Lookup::Unknown => None,
                })
            }
            Tok::Op(_) => None,
        }
    }
}

fn op_static(op: &str) -> &'static str {
    match op {
        "!" => "!",
        "-" => "-",
        "+" => "+",
        "~" => "~",
        "(" => "(",
        ")" => ")",
        _ => "",
    }
}

fn binary_prec(op: &str) -> Option<u8> {
    Some(match op {
        "||" => 1,
        "&&" => 2,
        "|" => 3,
        "^" => 4,
        "&" => 5,
        "==" | "!=" => 6,
        "<" | ">" | "<=" | ">=" => 7,
        "<<" | ">>" => 8,
        "+" | "-" => 9,
        "*" | "/" | "%" => 10,
        _ => return None,
    })
}

fn apply(op: &str, a: Val, b: Val) -> Val {
    match op {
        "&&" => match (a, b) {
            (Some(0), _) | (_, Some(0)) => Some(0),
            (Some(_), Some(_)) => Some(1),
            _ => None,
        },
        "||" => match (a, b) {
            (Some(x), _) if x != 0 => Some(1),
            (_, Some(y)) if y != 0 => Some(1),
            (Some(_), Some(_)) => Some(0),
            _ => None,
        },
        _ => {
            let (a, b) = (a?, b?);
            Some(match op {
                "|" => a | b,
                "^" => a ^ b,
                "&" => a & b,
                "==" => (a == b) as i64,
                "!=" => (a != b) as i64,
                "<" => (a < b) as i64,
                ">" => (a > b) as i64,
                "<=" => (a <= b) as i64,
                ">=" => (a >= b) as i64,
                "<<" => a.checked_shl(b.try_into().ok()?)?,
                ">>" => a.checked_shr(b.try_into().ok()?)?,
                "+" => a.wrapping_add(b),
                "-" => a.wrapping_sub(b),
                "*" => a.wrapping_mul(b),
                "/" => a.checked_div(b)?,
                "%" => a.checked_rem(b)?,
                _ => return None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(defs: &[(&str, Option<i64>)]) -> ConfigState {
        ConfigState {
            defined: defs.iter().map(|(n, v)| (n.to_string(), *v)).collect(),
        }
    }

    #[test]
    fn an_ifdef_the_configuration_leaves_off_is_excluded() {
        let src = "int a;\n#ifdef CONFIG_VTX\nint b;\n#else\nint c;\n#endif\nint d;\n";
        let c = compiled_lines(src, &state(&[]));
        assert!(c[1] && !c[3] && c[5] && c[7]);
        let c = compiled_lines(src, &state(&[("CONFIG_VTX", Some(1))]));
        assert!(c[3] && !c[5]);
    }

    #[test]
    fn values_compare_and_elif_is_evaluated() {
        let src =
            "#if MAX_NODES > 1\nint smp;\n#elif defined(UP)\nint up;\n#else\nint none;\n#endif\n";
        let c = compiled_lines(src, &state(&[("MAX_NODES", Some(1)), ("UP", None)]));
        assert!(!c[2] && c[4] && !c[6]);
    }

    #[test]
    fn a_reserved_name_or_a_macro_call_is_undecided() {
        let src = "#ifdef __GNUC__\nint g;\n#endif\n#if IS_ENABLED(X)\nint e;\n#endif\n#if defined(A) && 0\nint z;\n#endif\n";
        let c = compiled_lines(src, &state(&[]));
        assert!(!c[2] && !c[5] && !c[8]);
        let c = compiled_lines(src, &state(&[("__GNUC__", Some(12))]));
        assert!(c[2]);
    }

    #[test]
    fn a_project_header_derives_names_from_the_generated_ones() {
        let dir = tempfile::tempdir().unwrap();
        let gen = dir.path().join("gen_config.h");
        std::fs::write(
            &gen,
            "#define CONFIG_MAX_NUM_NODES 1\n/* disabled: CONFIG_ENABLE_SMP_SUPPORT */\n",
        )
        .unwrap();
        let config = dir.path().join("config.h");
        std::fs::write(
            &config,
            "#ifndef CONFIG_H\n#define CONFIG_H\n#include <gen_config.h>\n\
             #ifdef CONFIG_ENABLE_SMP_SUPPORT\n#define ENABLE_SMP_SUPPORT\n#endif\n\
             #ifndef CONFIG_ENABLE_SMP_SUPPORT\n#define UNIPROCESSOR 1\n#endif\n#endif\n",
        )
        .unwrap();
        let s = ConfigState::build(None, [gen.as_path()], [config.as_path()]);
        let c = compiled_lines(
            "#ifdef ENABLE_SMP_SUPPORT\nint smp;\n#endif\n#if UNIPROCESSOR\nint up;\n#endif\n",
            &s,
        );
        assert!(!c[2] && c[5]);
    }

    #[test]
    fn excluded_code_naming_a_generated_name_is_found() {
        let src = "#ifdef CONFIG_VTX\n    x = cap_ept_new(1); /* c */\n#endif\n// cap_ept_new\n";
        let c = compiled_lines(src, &state(&[]));
        let names = ["cap_ept_new".to_string()].into_iter().collect();
        assert!(excludes_code_naming(src, &c, &names));
        let other = ["other".to_string()].into_iter().collect();
        assert!(!excludes_code_naming(src, &c, &other));
        // One hop: an array sized by a generated value, used in an arm.
        let src = "int nodes[MAX];\n#if MAX > 1\n  nodes[i] = 0;\n#endif\n";
        let c = compiled_lines(src, &state(&[("MAX", Some(1))]));
        let names = ["MAX".to_string()].into_iter().collect();
        assert!(excludes_code_naming(src, &c, &names));
    }

    #[test]
    fn comments_with_non_ascii_text_are_stripped() {
        let mut open = false;
        assert_eq!(strip_comments("a /* “b” */ c // “d”", &mut open), "a   c ");
        assert_eq!(strip_comments("x /* “open", &mut open), "x  ");
        assert!(open);
        assert_eq!(strip_comments("still” */ y", &mut open), " y");
    }

    #[test]
    fn names_defined_in_a_header() {
        let names = names_defined_in(
            "#define N 1\nstatic inline int cap_get(const cap_t *c) { return 0; }\nint count(void);\ntypedef struct s s_t;\n",
        );
        for n in ["N", "cap_get", "count", "s_t"] {
            assert!(names.contains(&n.to_string()), "{n}: {names:?}");
        }
    }
}
