//! Assert-style macros that cannot be compiled out: a macro whose every
//! definition evaluates one parameter and, when it is false, calls something
//! that never returns.
//!
//! ADR-0011 basis 3 accepts "an assert or abort macro with no build-flag arm"
//! as proof in the scanned source, and ADR-0010 Decision 5 is the other half:
//! an `NDEBUG`-strippable `assert()` guards nothing, because the release
//! configuration exists. valkey's
//!
//! ```c
//! #define serverAssert(_e) (likely(_e) ? (void)0 : (_serverAssert(#_e, __FILE__, __LINE__), valkey_unreachable()))
//! ```
//!
//! has no other definition anywhere in the tree, so `serverAssert(p != NULL);`
//! guards what follows it in every configuration.
//!
//! Recognition is by what the macro *expands to*, never by its name:
//!
//! * **Every definition counts.** All `#define`s of a name across the project
//!   are kept, in every preprocessor arm, and a name qualifies only when each
//!   one is a check on the same parameter. A `#ifdef NDEBUG` arm defining it as
//!   `((void)0)` (or any other build-flag arm that does not check) disqualifies
//!   the name, which is ADR-0010's "every compilable configuration counts".
//!   Only a region the file itself proves dead (`#if 0`, ADR-0011 basis 2) is
//!   skipped. A variadic or token-pasting definition cannot be analyzed, so it
//!   disqualifies the name too.
//! * **The check is unconditional.** The recognized shapes are
//!   `C ? (void)0 : FAIL`, `!C ? FAIL : (void)0`, `C || FAIL`, `!C && FAIL`,
//!   and `if (!C) FAIL` (optionally in `do { ... } while (0)`), where `C`
//!   reduces to the parameter through parentheses, `!!`, `__builtin_expect`
//!   and truthiness-preserving macros such as `likely`. A runtime-gated
//!   variant like valkey's `debugServerAssert` —
//!   `(server.enable_debug_assert ? serverAssert(x) : (void)0)` — checks
//!   nothing when the switch is off, so it matches none of them (ADR-0011
//!   basis 5). It is also variadic.
//! * **FAIL never returns.** It calls a function the project knows is
//!   noreturn (`abort`, `exit`, `_Noreturn`, `__attribute__((noreturn))`,
//!   ...), `__builtin_trap`, or a macro every definition of which does. A
//!   branch that consists only of `__builtin_unreachable()` is an *assume*
//!   (`MBEDTLS_ASSUME`, miniaudio's `MA_ASSUME`): no check runs, the compiler
//!   is told the condition holds, which is basis 4, not proof. It counts only
//!   after a call that reports the failure, as in `serverAssert`'s
//!   `(_serverAssert(...), valkey_unreachable())`.
//! * **`assert` itself never qualifies**, whatever the project defines it as:
//!   `<assert.h>` supplies the `NDEBUG` definition (C11 7.2), and a file that
//!   includes it rather than the project's replacement header gets that one.

use std::collections::{HashMap, HashSet};

/// One `#define` of a name, as written.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MacroDefinition {
    /// `#define NAME(params) body`. Stringized parameters (`#p`) are replaced
    /// by `""` in `body`: they only ever produce a message string.
    Function {
        /// Parameter names in order.
        params: Vec<String>,
        /// Normalized replacement list.
        body: String,
    },
    /// `#define NAME body`.
    Object {
        /// Normalized replacement list.
        body: String,
    },
    /// A definition this module cannot reason about: variadic, token paste
    /// (`##`), or a parameter list that never closes.
    Opaque,
}

/// Every `#define` in `source`, in every preprocessor arm except those the
/// file itself proves dead, keyed by name, each distinct definition once.
pub fn collect_macro_definitions(source: &str) -> HashMap<String, Vec<MacroDefinition>> {
    let dead: Vec<(usize, usize)> = lang_parsing_substrate::dead_code_ranges(source)
        .into_iter()
        .map(|r| (r.start_line, r.end_line))
        .collect();
    let lines: Vec<&str> = source.lines().collect();
    let mut out: HashMap<String, Vec<MacroDefinition>> = HashMap::new();
    let mut i = 0;
    while i < lines.len() {
        let first_line = i + 1;
        let mut logical = String::new();
        while i < lines.len() {
            let te = lines[i].trim_end();
            i += 1;
            if let Some(stripped) = te.strip_suffix('\\') {
                logical.push_str(stripped);
                logical.push(' ');
            } else {
                logical.push_str(te);
                break;
            }
        }
        if dead
            .iter()
            .any(|&(s, e)| first_line >= s && first_line <= e)
        {
            continue;
        }
        if let Some((name, def)) = parse_define(&logical) {
            let defs = out.entry(name).or_default();
            if !defs.contains(&def) {
                defs.push(def);
            }
        }
    }
    out
}

/// Fold one file's definitions into the project-wide table.
pub fn merge_macro_definitions(
    into: &mut HashMap<String, Vec<MacroDefinition>>,
    from: HashMap<String, Vec<MacroDefinition>>,
) {
    for (name, defs) in from {
        let slot = into.entry(name).or_default();
        for def in defs {
            if !slot.contains(&def) {
                slot.push(def);
            }
        }
    }
}

/// `macro name -> index of the parameter it checks`, for every function-like
/// macro that, under every one of its definitions, returns only when that
/// parameter is true (see the module doc for exactly what qualifies).
pub fn abort_check_macros(
    defs: &HashMap<String, Vec<MacroDefinition>>,
    noreturn: &HashSet<String>,
) -> HashMap<String, usize> {
    let cx = Cx { defs, noreturn };
    let mut out = HashMap::new();
    for (name, alts) in defs {
        // `<assert.h>` always supplies the `NDEBUG`-strippable alternative.
        if name == "assert" {
            continue;
        }
        let mut checked: Option<usize> = None;
        let mut ok = !alts.is_empty();
        for def in alts {
            let MacroDefinition::Function { params, body } = def else {
                ok = false;
                break;
            };
            match cx.checked_param(body, params, 0) {
                Some(i) if checked.is_none_or(|c| c == i) => checked = Some(i),
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if let (true, Some(i)) = (ok, checked) {
            out.insert(name.clone(), i);
        }
    }
    out
}

/// The argument `stmt` checks, when `stmt` is an expression statement calling
/// one of `checks` (an [`abort_check_macros`] table): control passes the
/// statement only when that argument is true, in every configuration.
///
/// Anything else is `None`, and that includes every spelling of an
/// `NDEBUG`-strippable assert (`assert`, curl's `DEBUGASSERT`, hostap's
/// `WPA_ASSERT`), whatever its name suggests (ADR-0010 D5). A statement inside
/// a preprocessor wrapper is not looked into either: a check that only some
/// configurations compile guards nothing in the others.
pub fn abort_checked_argument<'a>(
    stmt: &tree_sitter::Node<'a>,
    source: &str,
    checks: &HashMap<String, usize>,
) -> Option<tree_sitter::Node<'a>> {
    if stmt.kind() != "expression_statement" {
        return None;
    }
    let call = stmt.named_child(0)?;
    if call.kind() != "call_expression" {
        return None;
    }
    let name = call
        .child_by_field_name("function")?
        .utf8_text(source.as_bytes())
        .ok()?;
    let &index = checks.get(name)?;
    call.child_by_field_name("arguments")?.named_child(index)
}

const MAX_DEPTH: usize = 8;

/// How a failure branch leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Exit {
    /// It may return.
    No,
    /// Only `__builtin_unreachable`: undefined behavior if reached, which a
    /// compiler may treat as an assumption. Not a check on its own.
    Assumed,
    /// A call that genuinely does not return.
    Real,
}

struct Cx<'a> {
    defs: &'a HashMap<String, Vec<MacroDefinition>>,
    noreturn: &'a HashSet<String>,
}

impl Cx<'_> {
    /// The parameter whose falsity `body` refuses to return from.
    fn checked_param(&self, body: &str, params: &[String], depth: usize) -> Option<usize> {
        let e = strip_void_cast(strip_group(body));
        if let Some(inner) = do_while_zero_body(e) {
            return self.statement_check(inner, params, depth);
        }
        if e.starts_with("if") && !is_ident_byte_at(e, 2) {
            return self.statement_check(e, params, depth);
        }
        if let Some((c, t, f)) = split_ternary(e) {
            let (i, positive) = self.polarity(c, params, depth)?;
            let (pass, fail) = if positive { (t, f) } else { (f, t) };
            return (is_noop(pass) && self.exits(fail, depth) == Exit::Real).then_some(i);
        }
        for (op, want) in [("||", true), ("&&", false)] {
            if let Some((l, r)) = split_top_level_binary(e, op) {
                let (i, positive) = self.polarity(l, params, depth)?;
                return (positive == want && self.exits(r, depth) == Exit::Real).then_some(i);
            }
        }
        None
    }

    /// `if (!C) FAIL` as the whole statement list (a `{ }` block holding only
    /// that `if` is the same thing).
    fn statement_check(&self, stmt: &str, params: &[String], depth: usize) -> Option<usize> {
        let s = strip_block(stmt.trim().trim_end_matches(';').trim());
        let rest = s.strip_prefix("if")?.trim_start();
        if !rest.starts_with('(') {
            return None;
        }
        let close = matching_close(rest, 0)?;
        let cond = &rest[1..close];
        let then = rest[close + 1..].trim();
        // An `else` would make the failure branch one of two alternatives.
        if contains_top_level_keyword(then, "else") {
            return None;
        }
        let (i, positive) = self.polarity(cond, params, depth)?;
        (!positive && self.exits(then, depth) == Exit::Real).then_some(i)
    }

    /// `(parameter index, positive)` when `e` is true exactly when that
    /// parameter is (positive) or is not (negative).
    fn polarity(&self, e: &str, params: &[String], depth: usize) -> Option<(usize, bool)> {
        if depth > MAX_DEPTH {
            return None;
        }
        let e = strip_group(e);
        if let Some(rest) = e.strip_prefix('!') {
            if !rest.starts_with('=') {
                let (i, p) = self.polarity(rest, params, depth + 1)?;
                return Some((i, !p));
            }
        }
        if let Some(i) = params.iter().position(|p| p == e) {
            return Some((i, true));
        }
        let (name, args) = whole_call(e)?;
        if name == "__builtin_expect" && args.len() == 2 {
            return self.polarity(&args[0], params, depth + 1);
        }
        // A macro that is its argument's truthiness under every definition
        // (`likely(x)`: `__builtin_expect(!!(x), 1)` or `(x)`).
        let alts = self.defs.get(name)?;
        let mut via: Option<(usize, bool)> = None;
        for def in alts {
            let MacroDefinition::Function { params: mp, body } = def else {
                return None;
            };
            if mp.len() != args.len() {
                return None;
            }
            let pol = self.polarity(body, mp, depth + 1)?;
            if via.is_some_and(|v| v != pol) {
                return None;
            }
            via = Some(pol);
        }
        let (j, pj) = via?;
        let (i, pi) = self.polarity(&args[j], params, depth + 1)?;
        Some((i, pi == pj))
    }

    /// Whether evaluating `e` unconditionally leaves.
    fn exits(&self, e: &str, depth: usize) -> Exit {
        if depth > MAX_DEPTH {
            return Exit::No;
        }
        let e = strip_void_cast(strip_group(e.trim().trim_end_matches(';').trim()));
        let parts: Vec<&str> = if e.starts_with('{') && e.ends_with('}') {
            split_top_level(&e[1..e.len() - 1], b';')
        } else {
            split_top_level(e, b',')
        };
        let mut reported = false;
        for part in parts {
            let part = strip_void_cast(strip_group(part.trim()));
            if part.is_empty() {
                continue;
            }
            let Some((name, _)) = whole_call(part) else {
                continue;
            };
            match self.callee_exits(name, depth + 1) {
                Exit::Real => return Exit::Real,
                Exit::Assumed if reported => return Exit::Real,
                Exit::Assumed => return Exit::Assumed,
                Exit::No => reported = true,
            }
        }
        Exit::No
    }

    fn callee_exits(&self, name: &str, depth: usize) -> Exit {
        if depth > MAX_DEPTH {
            return Exit::No;
        }
        match name {
            "__builtin_trap" => return Exit::Real,
            "__builtin_unreachable" => return Exit::Assumed,
            _ => {}
        }
        if let Some(alts) = self.defs.get(name) {
            // The weakest definition decides.
            let mut weakest = Exit::Real;
            for def in alts {
                let e = match def {
                    MacroDefinition::Object { body } => {
                        let b = strip_group(body);
                        if is_identifier(b) {
                            self.callee_exits(b, depth + 1)
                        } else {
                            Exit::No
                        }
                    }
                    MacroDefinition::Function { body, .. } => self.exits(body, depth + 1),
                    MacroDefinition::Opaque => Exit::No,
                };
                weakest = weakest.min(e);
            }
            return weakest;
        }
        if self.noreturn.contains(name) {
            Exit::Real
        } else {
            Exit::No
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing a `#define` line
// ---------------------------------------------------------------------------

fn parse_define(line: &str) -> Option<(String, MacroDefinition)> {
    let s = line.trim_start().strip_prefix('#')?.trim_start();
    let s = s.strip_prefix("define")?;
    if !s.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    let s = s.trim_start();
    let name_len = s
        .char_indices()
        .find(|&(i, c)| !(c == '_' || c.is_ascii_alphanumeric()) || (i == 0 && c.is_ascii_digit()))
        .map_or(s.len(), |(i, _)| i);
    if name_len == 0 {
        return None;
    }
    let name = s[..name_len].to_string();
    let after = &s[name_len..];
    if !after.starts_with('(') {
        return Some(match normalize_body(after, &[]) {
            Some(body) => (name, MacroDefinition::Object { body }),
            None => (name, MacroDefinition::Opaque),
        });
    }
    let Some(close) = after.find(')') else {
        return Some((name, MacroDefinition::Opaque));
    };
    let mut params = Vec::new();
    for p in after[1..close].split(',') {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        if p.contains("...") || !is_identifier(p) {
            return Some((name, MacroDefinition::Opaque));
        }
        params.push(p.to_string());
    }
    match normalize_body(&after[close + 1..], &params) {
        Some(body) => Some((name, MacroDefinition::Function { params, body })),
        None => Some((name, MacroDefinition::Opaque)),
    }
}

/// The replacement list with comments removed, every string or character
/// literal replaced by `""`/`0` (so no delimiter inside one is ever read as
/// syntax), and each `#param` stringize replaced by `""`. `None` for token
/// paste (`##`) or a `#` that is not a stringize of a parameter.
fn normalize_body(raw: &str, params: &[String]) -> Option<String> {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '/' if chars.get(i + 1) == Some(&'*') => {
                i += 2;
                while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                    i += 1;
                }
                i += 2;
                out.push(' ');
            }
            '/' if chars.get(i + 1) == Some(&'/') => break,
            '"' | '\'' => {
                i += 1;
                while i < chars.len() && chars[i] != c {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
                out.push_str(if c == '"' { "\"\"" } else { "0" });
            }
            '#' => {
                if chars.get(i + 1) == Some(&'#') {
                    return None;
                }
                let mut j = i + 1;
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                let start = j;
                while j < chars.len() && (chars[j] == '_' || chars[j].is_ascii_alphanumeric()) {
                    j += 1;
                }
                let ident: String = chars[start..j].iter().collect();
                if !params.contains(&ident) {
                    return None;
                }
                out.push_str("\"\"");
                i = j;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(out.trim().to_string())
}

// ---------------------------------------------------------------------------
// Expression-text helpers (over normalized bodies: no literals left to trip on)
// ---------------------------------------------------------------------------

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn is_ident_byte_at(s: &str, i: usize) -> bool {
    s.as_bytes()
        .get(i)
        .is_some_and(|&b| b == b'_' || b.is_ascii_alphanumeric())
}

/// Index of the bracket closing the one at byte `open`.
fn matching_close(s: &str, open: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (i, b) in s.bytes().enumerate().skip(open) {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Strip parentheses that enclose the whole expression, repeatedly.
fn strip_group(s: &str) -> &str {
    let mut s = s.trim();
    while s.starts_with('(') && matching_close(s, 0) == Some(s.len() - 1) {
        s = s[1..s.len() - 1].trim();
    }
    s
}

/// Strip a leading `(void)` cast.
fn strip_void_cast(s: &str) -> &str {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix('(') {
        if let Some(rest) = rest.trim_start().strip_prefix("void") {
            if let Some(rest) = rest.trim_start().strip_prefix(')') {
                return strip_group(rest);
            }
        }
    }
    t
}

/// A `{ ... }` block reduced to its contents.
fn strip_block(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('{') && matching_close(s, 0) == Some(s.len() - 1) {
        s[1..s.len() - 1].trim().trim_end_matches(';').trim()
    } else {
        s
    }
}

fn is_noop(s: &str) -> bool {
    let s = strip_void_cast(strip_group(s));
    s.is_empty() || s == "0"
}

/// `do { BODY } while (0)` → `BODY`.
fn do_while_zero_body(s: &str) -> Option<&str> {
    let rest = s.strip_prefix("do")?;
    if is_ident_byte_at(s, 2) {
        return None;
    }
    let rest = rest.trim_start();
    if !rest.starts_with('{') {
        return None;
    }
    let close = matching_close(rest, 0)?;
    let tail = rest[close + 1..].trim().trim_end_matches(';').trim();
    let cond = tail.strip_prefix("while")?.trim();
    (strip_group(cond) == "0").then(|| &rest[1..close])
}

/// `name(args)` spanning the whole of `s`.
fn whole_call(s: &str) -> Option<(&str, Vec<String>)> {
    let s = s.trim();
    let open = s.find('(')?;
    let name = s[..open].trim();
    if !is_identifier(name) || matching_close(s, open) != Some(s.len() - 1) {
        return None;
    }
    let inner = &s[open + 1..s.len() - 1];
    let args = if inner.trim().is_empty() {
        Vec::new()
    } else {
        split_top_level(inner, b',')
            .into_iter()
            .map(|a| a.trim().to_string())
            .collect()
    };
    Some((name, args))
}

/// `s` split at `sep` outside any bracket.
fn split_top_level(s: &str, sep: u8) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut last = 0;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            _ if b == sep && depth == 0 => {
                out.push(&s[last..i]);
                last = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[last..]);
    out
}

/// `C ? T : F` at the top level of `s`, splitting at the first `?` and its
/// matching `:`.
fn split_ternary(s: &str) -> Option<(&str, &str, &str)> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut q = None;
    let mut nested = 0i32;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'?' if depth == 0 => {
                if q.is_none() {
                    q = Some(i);
                } else {
                    nested += 1;
                }
            }
            b':' if depth == 0 && q.is_some() => {
                if nested == 0 {
                    let q = q.unwrap();
                    return Some((&s[..q], &s[q + 1..i], &s[i + 1..]));
                }
                nested -= 1;
            }
            _ => {}
        }
    }
    None
}

/// `L op R` at the top level, split at the first `op` (`||` or `&&`). Only
/// when no other top-level operator could bind looser: a comma or `?`
/// anywhere at the top level means the split is not the whole expression.
fn split_top_level_binary<'a>(s: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut at = None;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b',' | b'?' | b';' if depth == 0 => return None,
            _ if depth == 0 && at.is_none() && s[i..].starts_with(op) => at = Some(i),
            _ => {}
        }
    }
    let i = at?;
    // A second, different logical operator at the top level would change
    // grouping (`a || b && c`); refuse rather than guess.
    let other = if op == "||" { "&&" } else { "||" };
    if split_depth0_contains(s, other) {
        return None;
    }
    Some((&s[..i], &s[i + op.len()..]))
}

fn split_depth0_contains(s: &str, needle: &str) -> bool {
    let mut depth = 0i32;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            _ if depth == 0 && s[i..].starts_with(needle) => return true,
            _ => {}
        }
    }
    false
}

fn contains_top_level_keyword(s: &str, kw: &str) -> bool {
    let mut depth = 0i32;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            _ if depth == 0
                && s[i..].starts_with(kw)
                && (i == 0 || !is_ident_byte_at(s, i - 1))
                && !is_ident_byte_at(s, i + kw.len()) =>
            {
                return true
            }
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checks(src: &str) -> HashMap<String, usize> {
        let defs = collect_macro_definitions(src);
        let noreturn: HashSet<String> = ["abort", "exit"].iter().map(|s| s.to_string()).collect();
        abort_check_macros(&defs, &noreturn)
    }

    const VALKEY: &str = r#"
#if __GNUC__ >= 5
#define valkey_unreachable __builtin_unreachable
#else
#define valkey_unreachable abort
#endif
#if __GNUC__ >= 3
#define likely(x) __builtin_expect(!!(x), 1)
#else
#define likely(x) (x)
#endif
#define serverAssertWithInfo(_c, _o, _e) \
    (likely(_e) ? (void)0 : (_serverAssertWithInfo(_c, _o, #_e, __FILE__, __LINE__), valkey_unreachable()))
#define serverAssert(_e) (likely(_e) ? (void)0 : (_serverAssert(#_e, __FILE__, __LINE__), valkey_unreachable()))
#define debugServerAssert(...) (server.enable_debug_assert ? serverAssert(__VA_ARGS__) : (void)0)
#define assert(_e) (likely((_e)) ? (void)0 : (_serverAssert(#_e, __FILE__, __LINE__), valkey_unreachable()))
#define ValkeyModule_Assert(_e) ((_e) ? (void)0 : (ValkeyModule__Assert(#_e, __FILE__, __LINE__), exit(1)))
"#;

    #[test]
    fn valkey_asserts_are_checks() {
        let m = checks(VALKEY);
        assert_eq!(m.get("serverAssert"), Some(&0));
        assert_eq!(m.get("serverAssertWithInfo"), Some(&2));
        assert_eq!(m.get("ValkeyModule_Assert"), Some(&0));
    }

    #[test]
    fn runtime_gated_and_assert_stay_neutral() {
        let m = checks(VALKEY);
        assert!(!m.contains_key("debugServerAssert"));
        assert!(!m.contains_key("assert"));
        assert!(!m.contains_key("likely"));
    }

    #[test]
    fn runtime_gate_is_not_a_check_even_when_not_variadic() {
        let src = "#define M(x) (g_on ? ((x) ? (void)0 : abort()) : (void)0)\n";
        assert!(checks(src).is_empty());
    }

    #[test]
    fn ndebug_arm_disqualifies() {
        let src = "#ifdef NDEBUG\n#define CHECK(x) ((void)0)\n#else\n#define CHECK(x) do { if (!(x)) abort(); } while (0)\n#endif\n";
        assert!(checks(src).is_empty());
        // The same macro with only the checking arm qualifies.
        let one = "#define CHECK(x) do { if (!(x)) abort(); } while (0)\n";
        assert_eq!(checks(one).get("CHECK"), Some(&0));
    }

    #[test]
    fn if_zero_arm_is_not_a_configuration() {
        let src =
            "#if 0\n#define CHECK(x) ((void)0)\n#endif\n#define CHECK(x) ((x) || (abort(), 0))\n";
        assert_eq!(checks(src).get("CHECK"), Some(&0));
    }

    #[test]
    fn assume_is_not_a_check() {
        let src = "#define ASSUME(x) do { if (!(x)) __builtin_unreachable(); } while (0)\n";
        assert!(checks(src).is_empty());
    }

    #[test]
    fn non_returning_fail_branch_required() {
        let src = "#define WARN_ON(x) ((x) ? (void)0 : report(#x))\n";
        assert!(checks(src).is_empty());
    }

    #[test]
    fn negated_forms() {
        let src =
            "#define A(x) (!(x) ? abort() : (void)0)\n#define B(x) (void)(!(x) && (exit(1), 0))\n";
        let m = checks(src);
        assert_eq!(m.get("A"), Some(&0));
        assert_eq!(m.get("B"), Some(&0));
    }

    #[test]
    fn if_with_else_is_not_a_check() {
        let src = "#define M(x) if (!(x)) abort(); else log()\n";
        assert!(checks(src).is_empty());
    }
}
