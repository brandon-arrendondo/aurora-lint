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
///
/// Two passes: (1) a precise AST pass over `preproc_function_def` nodes; (2) a
/// textual error-correcting pass over the raw source that recovers definitions
/// tree-sitter buried in `ERROR` recovery regions (e.g. curl's `curl_setup.h`,
/// 1480 lines of nested `#if`, where `#define curlx_free(ptr) …` is misparsed
/// as `ERROR(#define) + call_expression` and never emitted as a
/// `preproc_function_def`). The AST pass is authoritative; the textual pass only
/// fills names the AST missed (`or_insert`), so clean files are unaffected.
pub fn collect_function_macros(root: &Node, source: &str) -> HashMap<String, FunctionMacro> {
    let mut out = HashMap::new();
    collect_rec(root, source, &mut out);
    for (name, m) in collect_function_macros_textual(source) {
        out.entry(name).or_insert(m);
    }
    out
}

/// Secondary, error-correcting collector: scans raw source line-by-line for
/// function-like `#define NAME(params) body` directives. Because the C
/// preprocessor is line-oriented, this is immune to however tree-sitter mangles
/// the surrounding C in error-recovery regions. Applies the same exclusions as
/// the AST pass (`#`/`##`, variadic) so the expander sees a consistent set.
pub fn collect_function_macros_textual(source: &str) -> HashMap<String, FunctionMacro> {
    let lines: Vec<&str> = source.lines().collect();
    let mut out = HashMap::new();
    let mut i = 0;
    while i < lines.len() {
        let (logical, next) = join_continuation(&lines, i);
        i = next;
        if let Some((name, m)) = parse_define_line(&logical) {
            // First definition wins (mirrors the AST pass): redefinitions across
            // platform `#ifdef` branches are ambiguous, so keep the first.
            out.entry(name).or_insert(m);
        }
    }
    out
}

/// Join a backslash-continued logical line starting at `start`. Returns the
/// spliced text (continuation backslashes removed, joined with a space) and the
/// index of the next unconsumed physical line.
fn join_continuation(lines: &[&str], start: usize) -> (String, usize) {
    let mut buf = String::new();
    let mut i = start;
    while i < lines.len() {
        let line = lines[i];
        let te = line.trim_end();
        if let Some(stripped) = te.strip_suffix('\\') {
            buf.push_str(stripped);
            buf.push(' ');
            i += 1;
        } else {
            buf.push_str(line);
            i += 1;
            break;
        }
    }
    (buf, i)
}

/// Parse one logical line as a function-like `#define`. Returns `None` for
/// non-directives, object-like macros, variadic macros, and macros using
/// `#`/`##`.
fn parse_define_line(line: &str) -> Option<(String, FunctionMacro)> {
    let s = line.trim_start();
    let s = s.strip_prefix('#')?;
    let s = s.trim_start().strip_prefix("define")?;
    // `define` must be a whole token (followed by whitespace), not a prefix
    // like `defined` or `definex`.
    if !s.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    let s = s.trim_start();

    // Macro name.
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() || !is_ident_start(chars[0]) {
        return None;
    }
    let mut k = 0;
    while k < chars.len() && is_ident_char(chars[k]) {
        k += 1;
    }
    let name: String = chars[..k].iter().collect();

    // Function-like requires '(' *immediately* after the name (no whitespace);
    // `#define NAME (x)` is object-like with body `(x)`.
    if k >= chars.len() || chars[k] != '(' {
        return None;
    }

    // Parse parameter list up to the matching ')'.
    let (params, body_start) = parse_param_list(&chars, k)?;
    let body_raw: String = chars[body_start..].iter().collect();
    let body = strip_comments(&body_raw).trim().to_string();

    if body_uses_paste_or_stringize(&body) {
        return None;
    }
    Some((name, FunctionMacro { params, body }))
}

/// Parse `(p1, p2, …)` starting at `open` (an index of `'('`). Returns the
/// parameter names and the index just past the closing `')'`. Bails on variadic
/// (`...`) macros (`None`).
fn parse_param_list(chars: &[char], open: usize) -> Option<(Vec<String>, usize)> {
    debug_assert_eq!(chars[open], '(');
    let mut params = Vec::new();
    let mut cur = String::new();
    let mut i = open + 1;
    let mut depth = 1i32;
    while i < chars.len() {
        match chars[i] {
            '(' => {
                depth += 1;
                cur.push('(');
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let t = cur.trim();
                    if !t.is_empty() {
                        params.push(t.to_string());
                    }
                    // Variadic param → unsupported.
                    if params.iter().any(|p| p.contains("...")) {
                        return None;
                    }
                    return Some((params, i + 1));
                }
                cur.push(')');
            }
            ',' if depth == 1 => {
                params.push(cur.trim().to_string());
                cur.clear();
            }
            c => cur.push(c),
        }
        i += 1;
    }
    None // unbalanced
}

/// Remove `/* … */` and `// …` comments from a macro replacement list, so the
/// textual body matches what the AST pass's `preproc_arg` yields.
fn strip_comments(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            out.push(' ');
        } else if chars[i] == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            break;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
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

    // ── Textual error-correcting collector ──────────────────────────────────

    #[test]
    fn textual_collects_function_like() {
        let t = collect_function_macros_textual(
            "#define curlx_free(ptr) curl_dbg_free(ptr, __LINE__, __FILE__)\n",
        );
        let m = t.get("curlx_free").expect("curlx_free collected");
        assert_eq!(m.params, vec!["ptr"]);
        assert_eq!(m.body, "curl_dbg_free(ptr, __LINE__, __FILE__)");
    }

    #[test]
    fn textual_skips_object_like() {
        // Space before '(' → object-like alias, not a function-like macro.
        let t = collect_function_macros_textual("#define curlx_free Curl_cfree\n");
        assert!(!t.contains_key("curlx_free"));
        let t2 = collect_function_macros_textual("#define PAREN (1 + 2)\n");
        assert!(!t2.contains_key("PAREN"));
    }

    #[test]
    fn textual_skips_variadic_and_paste() {
        let t = collect_function_macros_textual(
            "#define LOG(fmt, ...) printf(fmt, __VA_ARGS__)\n#define CAT(a,b) a##b\n",
        );
        assert!(!t.contains_key("LOG"));
        assert!(!t.contains_key("CAT"));
    }

    #[test]
    fn textual_joins_continuation() {
        let t = collect_function_macros_textual(
            "#define curlx_calloc(nbelem, size) \\\n  curl_dbg_calloc(nbelem, size, __LINE__, __FILE__)\n",
        );
        let m = t
            .get("curlx_calloc")
            .expect("collected across continuation");
        assert_eq!(m.params, vec!["nbelem", "size"]);
        assert!(m.body.contains("curl_dbg_calloc(nbelem, size"));
    }

    #[test]
    fn textual_strips_comments() {
        let t = collect_function_macros_textual("#define WRAP(x) real(x) /* trailing */\n");
        assert_eq!(t.get("WRAP").unwrap().body, "real(x)");
    }

    #[test]
    fn textual_indented_define_with_space_after_hash() {
        let t = collect_function_macros_textual("  #  define INDENT(x) ((x)+1)\n");
        assert!(t.contains_key("INDENT"));
    }

    #[test]
    fn does_not_match_defined_operator() {
        let t = collect_function_macros_textual("#if defined(FOO)\n#endif\n");
        assert!(t.is_empty());
    }

    #[test]
    fn merge_recovers_macro_in_error_region() {
        // A torture-header shape: a malformed construct forces tree-sitter into
        // ERROR recovery, so the following `#define` is NOT emitted as a
        // preproc_function_def — only the textual pass recovers it.
        let src = "#define BROKEN(a) a +++ ++ +\n\
                   int f(void) { return 1 } }\n\
                   #define recovered_free(ptr) free(ptr)\n";
        let mut p = CParser::new().unwrap();
        let tree = p.parse_source(src).unwrap();
        let ast_only = {
            let mut out = HashMap::new();
            collect_rec(&tree.root_node(), src, &mut out);
            out
        };
        let merged = collect_function_macros(&tree.root_node(), src);
        // Whatever the AST pass managed, the merged set must contain the wrapper.
        assert!(
            merged.contains_key("recovered_free"),
            "textual pass should recover recovered_free; ast_only={:?}",
            ast_only.keys().collect::<Vec<_>>()
        );
        assert_eq!(merged["recovered_free"].body, "free(ptr)");
    }
}
