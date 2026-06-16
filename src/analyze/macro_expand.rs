//! Textual expansion of function-like C macros — Phase 2 of the macro-expansion
//! plan (`docs/design/macro-expansion.md`).
//!
//! sqc has no preprocessor, so function-like macro *invocations* are opaque to
//! dataflow. This module collects function-like macro *definitions* from the
//! parsed source (the prescan pre-pass crosses headers, so vendored/project
//! macros are visible) and expands an invocation on demand via token-aware
//! parameter substitution plus recursive rescanning (C11 6.10.3). Wiring the
//! expanded text into the CFG/dataflow is increment 2b; this module is the
//! engine + the collector, independently unit-tested.
//!
//! Out of scope (intentionally left unexpanded — safe, same as today):
//!   * macros using `#` (stringize) or `##` (token paste) — need real cpp
//!     semantics and are rare (<1% in the surveyed codebases);
//!   * variadic macros (`...` / `__VA_ARGS__`);
//!   * object-like macros — handled separately by `const_eval`.
//
// Increment 2a delivered the collector + engine (unit-tested below). Increment
// 2b wires `collect_function_macros` into the prescan pre-pass / `ProjectContext`
// (so definitions are cached and available cross-file). The expander
// (`expand_invocation`) is consumed by the dataflow rules in a follow-up
// increment — driven by which macros the curl/hostap audits show cause FPs — at
// which point this allow is removed.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// A collected function-like macro definition.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FunctionMacro {
    /// Parameter names in order, e.g. `["x", "y"]`.
    pub params: Vec<String>,
    /// Raw replacement-list text, e.g. `(((x) < (y)) ? (x) : (y))`.
    pub body: String,
}

/// Maximum recursive-rescan depth (defense against pathological input; real
/// macro nesting is shallow).
const MAX_EXPAND_DEPTH: usize = 32;

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}
fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Collect function-like macro definitions from a parsed translation unit.
/// Skips macros that use `#`/`##` or are variadic (left unexpanded downstream).
pub fn collect_function_macros(root: &Node, source: &str) -> HashMap<String, FunctionMacro> {
    let mut out = HashMap::new();
    collect_rec(root, source, &mut out);
    out
}

fn collect_rec(node: &Node, source: &str, out: &mut HashMap<String, FunctionMacro>) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "preproc_function_def" => {
                    if let Some((name, m)) = parse_function_def(&child, source) {
                        // First definition wins; redefinitions (e.g. platform
                        // #ifdef branches) are ambiguous, so keep the first.
                        out.entry(name).or_insert(m);
                    }
                }
                kind if kind.starts_with("preproc_") => collect_rec(&child, source, out),
                _ => {}
            }
        }
    }
}

fn parse_function_def(node: &Node, source: &str) -> Option<(String, FunctionMacro)> {
    let name = node
        .child_by_field_name("name")?
        .utf8_text(source.as_bytes())
        .ok()?
        .to_string();

    let params_node = node.child_by_field_name("parameters")?;
    let mut params = Vec::new();
    for i in 0..params_node.child_count() {
        if let Some(p) = params_node.child(i) {
            match p.kind() {
                "identifier" => params.push(p.utf8_text(source.as_bytes()).ok()?.to_string()),
                // variadic param: bail (unsupported)
                "..." => return None,
                _ => {}
            }
        }
    }

    let body = node
        .child_by_field_name("value")
        .and_then(|v| v.utf8_text(source.as_bytes()).ok())
        .unwrap_or("")
        .trim()
        .to_string();

    // Skip stringize / token-paste — require real preprocessor semantics.
    if body_uses_paste_or_stringize(&body) {
        return None;
    }

    Some((name, FunctionMacro { params, body }))
}

/// Detect `#`/`##` operators in a replacement list, ignoring occurrences inside
/// string/char literals.
fn body_uses_paste_or_stringize(body: &str) -> bool {
    let bytes: Vec<char> = body.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            '"' | '\'' => {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    if bytes[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
            }
            '#' => return true,
            _ => i += 1,
        }
    }
    false
}

/// Expand a single function-like macro invocation `name(args...)` using `table`,
/// recursively rescanning the result. Returns `None` if `name` is not a known
/// function-like macro or the argument count does not match the parameters.
pub fn expand_invocation(
    table: &HashMap<String, FunctionMacro>,
    name: &str,
    args: &[String],
) -> Option<String> {
    let mut active = HashSet::new();
    expand_named(table, name, args, &mut active, 0)
}

fn expand_named(
    table: &HashMap<String, FunctionMacro>,
    name: &str,
    args: &[String],
    active: &mut HashSet<String>,
    depth: usize,
) -> Option<String> {
    if depth >= MAX_EXPAND_DEPTH || active.contains(name) {
        return None;
    }
    let m = table.get(name)?;
    if m.params.len() != args.len() {
        return None; // arity mismatch — do not expand
    }
    let mut map = HashMap::new();
    for (p, a) in m.params.iter().zip(args.iter()) {
        map.insert(p.clone(), a.clone());
    }
    let substituted = substitute_params(&m.body, &map);
    active.insert(name.to_string());
    let rescanned = rescan(table, &substituted, active, depth + 1);
    active.remove(name);
    Some(rescanned)
}

/// Replace whole-identifier occurrences of parameter names in `body` with their
/// argument text. Skips identifiers inside string/char literals.
fn substitute_params(body: &str, map: &HashMap<String, String>) -> String {
    let chars: Vec<char> = body.chars().collect();
    let mut out = String::with_capacity(body.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' || c == '\'' {
            let quote = c;
            out.push(c);
            i += 1;
            while i < chars.len() {
                out.push(chars[i]);
                if chars[i] == '\\' && i + 1 < chars.len() {
                    out.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                if chars[i] == quote {
                    i += 1;
                    break;
                }
                i += 1;
            }
        } else if is_ident_start(c) {
            let start = i;
            while i < chars.len() && is_ident_char(chars[i]) {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            if let Some(repl) = map.get(&ident) {
                out.push_str(repl);
            } else {
                out.push_str(&ident);
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Rescan expanded text, expanding any further function-like macro invocations.
fn rescan(
    table: &HashMap<String, FunctionMacro>,
    text: &str,
    active: &mut HashSet<String>,
    depth: usize,
) -> String {
    if depth >= MAX_EXPAND_DEPTH {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' || c == '\'' {
            let quote = c;
            out.push(c);
            i += 1;
            while i < chars.len() {
                out.push(chars[i]);
                if chars[i] == '\\' && i + 1 < chars.len() {
                    out.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                if chars[i] == quote {
                    i += 1;
                    break;
                }
                i += 1;
            }
        } else if is_ident_start(c) {
            let start = i;
            while i < chars.len() && is_ident_char(chars[i]) {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            // Is this a function-like macro invocation? Look for a '(' after
            // optional whitespace.
            let mut j = i;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            if table.contains_key(&ident)
                && !active.contains(&ident)
                && j < chars.len()
                && chars[j] == '('
            {
                if let Some((args, end)) = parse_call_args(&chars, j) {
                    if let Some(expanded) = expand_named(table, &ident, &args, active, depth) {
                        out.push_str(&expanded);
                        i = end;
                        continue;
                    }
                }
            }
            out.push_str(&ident);
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Parse a parenthesized, comma-separated argument list starting at `open`
/// (which must index a `'('`). Returns the argument texts (trimmed) and the
/// index just past the closing `')'`. Respects nested parens/brackets/braces
/// and string/char literals.
fn parse_call_args(chars: &[char], open: usize) -> Option<(Vec<String>, usize)> {
    debug_assert_eq!(chars[open], '(');
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut i = open;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '"' | '\'' => {
                let quote = c;
                cur.push(c);
                i += 1;
                while i < chars.len() {
                    cur.push(chars[i]);
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        cur.push(chars[i + 1]);
                        i += 2;
                        continue;
                    }
                    if chars[i] == quote {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            '(' | '[' | '{' => {
                depth += 1;
                if depth > 1 {
                    cur.push(c);
                }
                i += 1;
            }
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    // end of arg list
                    let trimmed = cur.trim();
                    // An empty `()` call has zero args, not one empty arg.
                    if !(args.is_empty() && trimmed.is_empty()) {
                        args.push(trimmed.to_string());
                    }
                    return Some((args, i + 1));
                }
                cur.push(c);
                i += 1;
            }
            ',' if depth == 1 => {
                args.push(cur.trim().to_string());
                cur.clear();
                i += 1;
            }
            _ => {
                cur.push(c);
                i += 1;
            }
        }
    }
    None // unbalanced
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::CParser;

    fn table(src: &str) -> HashMap<String, FunctionMacro> {
        let mut p = CParser::new().unwrap();
        let tree = p.parse_source(src).unwrap();
        collect_function_macros(&tree.root_node(), src)
    }

    #[test]
    fn collects_simple_function_macro() {
        let t = table("#define MIN(x,y) (((x) < (y)) ? (x) : (y))\n");
        let m = t.get("MIN").expect("MIN collected");
        assert_eq!(m.params, vec!["x", "y"]);
        assert!(m.body.contains("(x) < (y)"));
    }

    #[test]
    fn skips_stringize_and_paste() {
        let t = table("#define STR(x) #x\n#define CAT(a,b) a##b\n#define OK(a) ((a)+1)\n");
        assert!(!t.contains_key("STR"));
        assert!(!t.contains_key("CAT"));
        assert!(t.contains_key("OK"));
    }

    #[test]
    fn skips_variadic() {
        let t = table("#define LOG(fmt, ...) printf(fmt, __VA_ARGS__)\n");
        assert!(!t.contains_key("LOG"));
    }

    #[test]
    fn expands_simple() {
        let t = table("#define MIN(x,y) (((x) < (y)) ? (x) : (y))\n");
        let out = expand_invocation(&t, "MIN", &["a".into(), "b+1".into()]).unwrap();
        assert_eq!(out, "(((a) < (b+1)) ? (a) : (b+1))");
    }

    #[test]
    fn expands_deref_macro() {
        let t = table("#define ORIGVFS(p) ((sqlite3_vfs*)((p)->pAppData))\n");
        let out = expand_invocation(&t, "ORIGVFS", &["pFile".into()]).unwrap();
        assert_eq!(out, "((sqlite3_vfs*)((pFile)->pAppData))");
    }

    #[test]
    fn arity_mismatch_returns_none() {
        let t = table("#define MIN(x,y) ((x)<(y)?(x):(y))\n");
        assert!(expand_invocation(&t, "MIN", &["a".into()]).is_none());
    }

    #[test]
    fn does_not_substitute_inside_string() {
        let t = table("#define TAG(x) \"x is here\" x\n");
        // The "x" inside the string literal must not be replaced.
        let out = expand_invocation(&t, "TAG", &["v".into()]).unwrap();
        assert_eq!(out, "\"x is here\" v");
    }

    #[test]
    fn recursive_rescan_nested_macro() {
        let t = table("#define SQUARE(z) ((z)*(z))\n#define DIST(a) SQUARE(a)\n");
        let out = expand_invocation(&t, "DIST", &["n+1".into()]).unwrap();
        assert_eq!(out, "((n+1)*(n+1))");
    }

    #[test]
    fn self_reference_does_not_loop() {
        // `#define A(x) A(x)` must not infinitely recurse; the inner A is left
        // unexpanded once A is active.
        let t = table("#define A(x) A((x)+1)\n");
        let out = expand_invocation(&t, "A", &["v".into()]).unwrap();
        assert_eq!(out, "A((v)+1)");
    }

    #[test]
    fn nested_call_args_with_commas() {
        let t = table("#define ADD(a,b) ((a)+(b))\n#define ID(x) (x)\n");
        // ID(ADD(1,2)) — the comma is inside a nested call, one arg to ID.
        let out = expand_invocation(&t, "ID", &["ADD(1,2)".into()]).unwrap();
        assert_eq!(out, "(((1)+(2)))");
    }
}
