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
// Increment 2a delivered the collector + engine. Increment 2b wired
// `collect_function_macros` into the prescan pre-pass / `ProjectContext` (so
// definitions are cached and available cross-file). The expander
// (`expand_invocation`) is consumed by the dataflow rules:
//   * 2c-ii — `macro_output_param_indices` feeds EXP33-C's read-checker and the
//     init-state transfer to recognize macro output arguments (`CF_DATA_SAVE`);
//   * 2c-iii — `macro_nulls_param_indices` feeds MEM30-C to recognize "safe
//     free" macros that free AND null their argument (`Curl_safefree`).

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

/// Every function-like definition found in `source`, keyed by macro name and
/// keeping **all** definitions of a name rather than only the first.
///
/// [`collect_function_macros`] deliberately keeps one body per name: an
/// expander has to pick a branch, and picking the first is as defensible as
/// any. A caller asking the different question "could a call to this macro
/// touch a variable named `x` in my scope?" cannot pick — the alternatives
/// live in mutually exclusive `#ifdef` branches, and the one that matters is
/// not usually the first. sqlite's `complete.c` is the shape: `IdChar(C)` is
/// defined twice, `#ifdef SQLITE_ASCII` as a pure table lookup and `#ifdef
/// SQLITE_EBCDIC` as `(((c=C)>=0x42 && …))`, which assigns and reads a
/// caller-scope `c`. Only the second definition explains the `unsigned char
/// c;` sitting under the matching `#ifdef` in the caller.
///
/// Textual scan only (no AST pass): the point here is coverage of every
/// preprocessor branch, and the line-oriented scanner already sees all of
/// them.
pub fn collect_function_macro_alternatives(source: &str) -> HashMap<String, Vec<FunctionMacro>> {
    let lines: Vec<&str> = source.lines().collect();
    let mut out: HashMap<String, Vec<FunctionMacro>> = HashMap::new();
    let mut i = 0;
    while i < lines.len() {
        let (logical, next) = join_continuation(&lines, i);
        i = next;
        if let Some((name, m)) = parse_define_line(&logical) {
            let alts = out.entry(name).or_default();
            if !alts.contains(&m) {
                alts.push(m);
            }
        }
    }
    out
}

/// True if `m`'s replacement list mentions `var` as a *free* identifier —
/// one that is not one of the macro's own parameters, and so binds to
/// whatever `var` names at the call site.
///
/// This is C semantics, not a heuristic: a macro is textual substitution, so
/// a free `c` in the replacement list really does read (or write) the `c` in
/// scope where the macro is invoked. Identifiers are matched whole-token, so
/// `c` does not match `cnt` or `pc`.
pub fn macro_references_free_identifier(m: &FunctionMacro, var: &str) -> bool {
    if var.is_empty() || m.params.iter().any(|p| p == var) {
        return false;
    }
    let chars: Vec<char> = m.body.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if is_ident_start(chars[i]) {
            let start = i;
            while i < chars.len() && is_ident_char(chars[i]) {
                i += 1;
            }
            let tok: String = chars[start..i].iter().collect();
            if tok == var {
                return true;
            }
        } else {
            i += 1;
        }
    }
    false
}

/// Every identifier in `m`'s replacement list that is *free* — not one of
/// the macro's own parameters — and so binds to whatever that name means at
/// the call site. The set form of [`macro_references_free_identifier`], for
/// callers collecting names rather than testing one.
pub fn macro_free_identifiers(m: &FunctionMacro) -> HashSet<String> {
    let mut out = HashSet::new();
    let chars: Vec<char> = m.body.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if is_ident_start(chars[i]) {
            let start = i;
            while i < chars.len() && is_ident_char(chars[i]) {
                i += 1;
            }
            let tok: String = chars[start..i].iter().collect();
            if !m.params.contains(&tok) {
                out.insert(tok);
            }
        } else {
            i += 1;
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
pub(crate) fn parse_call_args(chars: &[char], open: usize) -> Option<(Vec<String>, usize)> {
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

/// Parameter indices that a function-like macro *writes* — i.e. the macro body
/// assigns to the (whole) parameter, directly or after expanding nested macros
/// drawn from `table`. Such positions are macro **output arguments**: a
/// bare-identifier argument there is being written by the macro, not read, so it
/// is not a use of uninitialized memory and is initialized afterwards.
///
/// Example: curl's `CF_DATA_SAVE(save, cf, data)` expands to
/// `do { (save) = …; … } while(0)`, so index 0 (`save`) is an output. The other
/// args (`cf`, `data`) only appear as reads, so they are not outputs.
///
/// Detection is deliberately conservative — only *whole-object* assignment
/// (`(param) = …`) counts. Field/element/deref writes (`param->f = …`,
/// `param[i] = …`, `*param = …`) read `param` first and so are NOT outputs.
pub fn macro_output_param_indices(
    table: &HashMap<String, FunctionMacro>,
    name: &str,
) -> Vec<usize> {
    let m = match table.get(name) {
        Some(m) => m,
        None => return Vec::new(),
    };
    if m.params.is_empty() {
        return Vec::new();
    }
    // Substitute each parameter with a unique sentinel, then fully expand (so
    // nested macros from the same body — `CF_CTX_CALL_DATA`, `CURL_UNCONST` —
    // resolve and we see the real lvalue context of each parameter).
    let sentinels: Vec<String> = (0..m.params.len())
        .map(|i| format!("__SQC_MOUT_{i}__"))
        .collect();
    let expanded = match expand_invocation(table, name, &sentinels) {
        Some(e) => e,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for (i, sent) in sentinels.iter().enumerate() {
        if is_whole_assignment_target(&expanded, sent) {
            out.push(i);
        }
    }
    out
}

/// True if a function-like macro's replacement list begins with a `case`
/// label — e.g. sqlite's `#define CASE(i,str) case i: assert(...);`, invoked
/// as `CASE(0, "xColumnCount") { ... }`. Tree-sitter parses the invocation as
/// an ordinary `call_expression` (the real `case` label is hidden inside the
/// macro body it can't see), so a switch-statement structural check walking
/// the AST directly would misread the invocation as a plain statement
/// preceding the first visible label. Callers use this to recognize such an
/// invocation as itself being the case label.
///
/// No parameter substitution is needed: the leading `case` token is a literal
/// keyword in the replacement list, never a parameter, so it is visible
/// before expansion.
pub fn macro_expands_to_case_label(table: &HashMap<String, FunctionMacro>, name: &str) -> bool {
    let m = match table.get(name) {
        Some(m) => m,
        None => return false,
    };
    let body = m.body.trim_start();
    match body.strip_prefix("case") {
        Some(rest) => !rest.starts_with(|c: char| is_ident_char(c)),
        None => false,
    }
}

/// Parameter indices that a function-like macro frees-and-nulls: the body
/// assigns the (whole) parameter the null pointer constant (`(param) = NULL`),
/// directly or after expanding nested macros from `table`. This is the
/// "safe free" idiom — curl `Curl_safefree(ptr)` expands to
/// `do { curlx_free(ptr); (ptr) = NULL; } while(0)`, so index 0 is reported.
///
/// MEM30-C already treats such macros as a free (the name contains `FREE`), but
/// cannot see the `= NULL`; consuming this list lets it clear the argument's
/// freed state — exactly as if the caller had written `free(p); p = NULL;` —
/// removing use-after-free / double-free false positives on safe-free wrappers.
/// (mosquitto `mosquitto_FREE`, `SAFE_FREE` share the idiom — engine, not
/// allowlist.)
pub fn macro_nulls_param_indices(table: &HashMap<String, FunctionMacro>, name: &str) -> Vec<usize> {
    let m = match table.get(name) {
        Some(m) => m,
        None => return Vec::new(),
    };
    if m.params.is_empty() {
        return Vec::new();
    }
    let sentinels: Vec<String> = (0..m.params.len())
        .map(|i| format!("__SQC_MNULL_{i}__"))
        .collect();
    let expanded = match expand_invocation(table, name, &sentinels) {
        Some(e) => e,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for (i, sent) in sentinels.iter().enumerate() {
        if is_null_assignment_target(&expanded, sent) {
            out.push(i);
        }
    }
    out
}

/// Parameter indices that a function-like macro **writes through**: either a
/// whole-object assignment (`(param) = …`, same as
/// [`macro_output_param_indices`]) or a write through the pointer/array itself
/// — `param->field = …`, `param[i] = …`, `*param = …`. The latter forms are
/// deliberately *excluded* from `macro_output_param_indices` because they
/// presuppose `param` already holds a valid address (relevant to EXP33-C's
/// uninitialized-*scalar* question), but they are exactly what EXP34-C
/// (null-pointer) and ARR00-C (array-bounds) care about: successfully writing
/// through `param` proves it was non-null / in-bounds, the same idiom
/// `function_summary.rs::modifies_params` tracks for real (non-macro)
/// functions via `line_has_arrow_or_subscript_write`.
///
/// Example: sqlite's `fts3GetVarint32(p, piVal)` expands with a deref write
/// `*piVal = *(u8*)(p)`, so index 1 (`piVal`) is reported.
pub fn macro_writes_param_indices(
    table: &HashMap<String, FunctionMacro>,
    name: &str,
) -> Vec<usize> {
    let m = match table.get(name) {
        Some(m) => m,
        None => return Vec::new(),
    };
    if m.params.is_empty() {
        return Vec::new();
    }
    let sentinels: Vec<String> = (0..m.params.len())
        .map(|i| format!("__SQC_MWR_{i}__"))
        .collect();
    let expanded = match expand_invocation(table, name, &sentinels) {
        Some(e) => e,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for (i, sent) in sentinels.iter().enumerate() {
        if is_whole_assignment_target(&expanded, sent) || writes_through_pointer(&expanded, sent) {
            out.push(i);
        }
    }
    out
}

/// True if `ident` is written through a pointer/array access in `text`:
/// `ident->field = …`, `ident[i] = …`, or a dereference write `*ident = …` /
/// `*(ident) = …`. Mirrors `function_summary.rs::line_has_arrow_or_subscript_write`
/// (arrow/subscript half) plus a deref-write check for the `*ident =` form,
/// which real-function analysis doesn't need separately (a function body's
/// `*param = x` is textually indistinguishable from other dereferences there,
/// but here we search the fully-expanded, sentinel-substituted macro body so
/// a direct char scan is precise). See [`macro_writes_param_indices`].
fn writes_through_pointer(text: &str, ident: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let id: Vec<char> = ident.chars().collect();
    let (n, m) = (chars.len(), id.len());
    if m == 0 {
        return false;
    }
    let mut i = 0;
    while i + m <= n {
        if chars[i..i + m] == id[..] {
            let prev_ok = i == 0 || !is_ident_char(chars[i - 1]);
            let next_ok = i + m >= n || !is_ident_char(chars[i + m]);
            if prev_ok && next_ok {
                // Arrow/subscript write: skip wrapping `)`/whitespace after the
                // identifier (handles `(ident)->f` / `(ident)[0]`), then check
                // for `->`/`[` followed eventually by a genuine `=`.
                let mut j = i + m;
                while j < n && (chars[j].is_whitespace() || chars[j] == ')') {
                    j += 1;
                }
                let is_arrow = j + 1 < n && chars[j] == '-' && chars[j + 1] == '>';
                let is_subscript = j < n && chars[j] == '[';
                if is_arrow || is_subscript {
                    if let Some(eq_pos) = find_genuine_eq_after(&chars, j) {
                        let _ = eq_pos;
                        return true;
                    }
                }
                // Deref write: `*ident =` or `*(ident) =` (wrapping parens
                // between the `*` and the identifier).
                let mut b = i;
                while b > 0 && (chars[b - 1].is_whitespace() || chars[b - 1] == '(') {
                    b -= 1;
                }
                if b > 0 && chars[b - 1] == '*' {
                    let mut k = i + m;
                    while k < n && (chars[k].is_whitespace() || chars[k] == ')') {
                        k += 1;
                    }
                    if k < n && chars[k] == '=' && (k + 1 >= n || chars[k + 1] != '=') {
                        return true;
                    }
                }
            }
        }
        i += 1;
    }
    false
}

/// Starting from `from` (index of `-`/`[`), find the next genuine assignment
/// `=` (excluding `==`/`!=`/`<=`/`>=`) at or after this access, returning its
/// index. Bounded to the same textual "access chain" by simply scanning
/// forward — good enough for the short, sentinel-substituted macro bodies
/// this operates on.
fn find_genuine_eq_after(chars: &[char], from: usize) -> Option<usize> {
    let n = chars.len();
    let mut search_from = from;
    while search_from < n {
        if chars[search_from] == '=' {
            let before = if search_from > 0 {
                chars[search_from - 1]
            } else {
                ' '
            };
            let after = if search_from + 1 < n {
                chars[search_from + 1]
            } else {
                ' '
            };
            let is_comparison =
                before == '!' || before == '<' || before == '>' || before == '=' || after == '=';
            if !is_comparison {
                return Some(search_from);
            }
        }
        search_from += 1;
    }
    None
}

/// A "pure forwarding" macro: one whose entire body is a single call to
/// another (real, non-macro) function, passing each of its own parameters
/// through -- verbatim or wrapped in casts/parens -- as call arguments,
/// possibly interleaved with extra literal arguments the macro adds itself.
/// curl's `#define Curl_rand(a, b, c) Curl_rand_bytes(a, TRUE, b, c)` is the
/// motivating case (task 589): the macro's own body has no assignment for
/// [`macro_output_param_indices`] to see, but the forwarded function
/// (`Curl_rand_bytes`) genuinely writes through one of those args, per its
/// `FunctionSummary::modifies_params`. Callers resolve output-param indices
/// for a forwarding macro by mapping the forwarded function's
/// `modifies_params` (callee-argument-position-indexed) back through
/// `param_map` to the macro's own parameter indices.
///
/// Returns `(forwarded_function_name, param_map)` where `param_map[i]` is
/// `Some(j)` when the callee's `i`-th argument is (after stripping
/// casts/grouping parens) exactly the macro's `j`-th own parameter,
/// unmodified -- and `None` when that argument position is something else
/// (a literal, an expression combining/transforming params, etc). This is
/// deliberately conservative: a macro that recombines or drops a parameter
/// before forwarding does not get positional credit for that argument, so a
/// caller can never misattribute a write to the wrong macro parameter.
pub fn macro_forwarding_target(
    table: &HashMap<String, FunctionMacro>,
    name: &str,
) -> Option<(String, Vec<Option<usize>>)> {
    let m = table.get(name)?;
    if m.params.is_empty() {
        return None;
    }
    let sentinels: Vec<String> = (0..m.params.len())
        .map(|i| format!("__SQC_MFWD_{i}__"))
        .collect();
    let expanded = expand_invocation(table, name, &sentinels)?;
    let body = expanded.trim().trim_end_matches(';').trim();

    // Must be exactly one call expression: NAME(args), nothing else around it.
    let open = body.find('(')?;
    if !body.ends_with(')') {
        return None;
    }
    let callee = body[..open].trim();
    if callee.is_empty()
        || !callee.starts_with(is_ident_start)
        || !callee.chars().all(is_ident_char)
    {
        return None;
    }
    // Refuse chains into another macro -- callers resolve one hop via a real
    // FunctionSummary, not another expansion.
    if table.contains_key(callee) {
        return None;
    }

    let args_text = &body[open + 1..body.len() - 1];
    let args = split_top_level_commas(args_text);
    let param_map = args
        .iter()
        .map(|arg| {
            let unwrapped = unwrap_cast_and_parens(arg.trim());
            sentinels.iter().position(|s| s == unwrapped)
        })
        .collect();
    Some((callee.to_string(), param_map))
}

/// Split `text` on top-level commas (depth 0 parens), trimming nothing --
/// callers trim each piece themselves. Empty input yields an empty `Vec`
/// (zero arguments), matching a niladic call `f()`.
fn split_top_level_commas(text: &str) -> Vec<&str> {
    if text.trim().is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b',' if depth == 0 => {
                out.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&text[start..]);
    out
}

/// Strip outer grouping parens and cast expressions from `s`, repeatedly:
/// `(rnd)` -> `rnd`, `(unsigned char *)rnd` -> `rnd`,
/// `((unsigned char *)(rnd))` -> `rnd`. Anything else (an operator, a
/// function call, more than one token left after stripping a leading
/// parenthesized group) is left as-is, since it can no longer be a bare
/// parameter reference.
fn unwrap_cast_and_parens(s: &str) -> &str {
    let mut s = s.trim();
    if !s.is_ascii() {
        // Byte offsets below are computed over `chars()`; only valid to
        // slice `s` with them when every char is one byte. Non-ASCII text
        // in this position is not a bare parameter reference anyway.
        return s;
    }
    loop {
        if !s.starts_with('(') {
            return s;
        }
        let chars: Vec<char> = s.chars().collect();
        let mut depth = 0i32;
        let mut close = None;
        for (i, &c) in chars.iter().enumerate() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else { return s };
        if close == chars.len() - 1 {
            // The whole string is one parenthesized group: `(rnd)`.
            s = s[1..s.len() - 1].trim();
        } else {
            // A leading group followed by more text: a cast, `(T)rest`.
            let rest = s[close + 1..].trim();
            if rest.is_empty() {
                return s;
            }
            s = rest;
        }
    }
}

/// Deallocation functions recognized by [`macro_frees_param_indices`].
const DEALLOC_FUNCTIONS: &[&str] = &["free", "fclose", "close"];

/// Parameter indices that a function-like macro releases: the body calls one
/// of `free`/`fclose`/`close` with the (possibly wrapped) parameter as an
/// argument, directly or after expanding nested macros from `table`. Unlike
/// [`macro_nulls_param_indices`] this does not require the macro to also null
/// the pointer — callers that only need to know the resource was released
/// (e.g. MEM12-C's early-return leak check) don't need the null-clearing
/// signal.
pub fn macro_frees_param_indices(table: &HashMap<String, FunctionMacro>, name: &str) -> Vec<usize> {
    let m = match table.get(name) {
        Some(m) => m,
        None => return Vec::new(),
    };
    if m.params.is_empty() {
        return Vec::new();
    }
    let sentinels: Vec<String> = (0..m.params.len())
        .map(|i| format!("__SQC_MFREE_{i}__"))
        .collect();
    let expanded = match expand_invocation(table, name, &sentinels) {
        Some(e) => e,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for (i, sent) in sentinels.iter().enumerate() {
        if calls_dealloc_fn_with_arg(&expanded, sent) {
            out.push(i);
        }
    }
    out
}

/// True if `text` contains a call to one of [`DEALLOC_FUNCTIONS`] with `ident`
/// appearing as one of its arguments.
fn calls_dealloc_fn_with_arg(text: &str, ident: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    for &fn_name in DEALLOC_FUNCTIONS {
        let fname: Vec<char> = fn_name.chars().collect();
        let flen = fname.len();
        let mut i = 0;
        while i + flen <= n {
            if chars[i..i + flen] == fname[..] {
                let prev_ok = i == 0 || !is_ident_char(chars[i - 1]);
                let mut j = i + flen;
                while j < n && chars[j].is_whitespace() {
                    j += 1;
                }
                if prev_ok && j < n && chars[j] == '(' {
                    // Find the matching close paren, then check whether
                    // `ident` occurs (as a whole token) inside the argument
                    // list.
                    let mut depth = 0i32;
                    let mut k = j;
                    let mut close = None;
                    while k < n {
                        match chars[k] {
                            '(' => depth += 1,
                            ')' => {
                                depth -= 1;
                                if depth == 0 {
                                    close = Some(k);
                                    break;
                                }
                            }
                            _ => {}
                        }
                        k += 1;
                    }
                    if let Some(close) = close {
                        let arg_text: String = chars[j + 1..close].iter().collect();
                        if contains_whole_ident(&arg_text, ident) {
                            return true;
                        }
                    }
                }
            }
            i += 1;
        }
    }
    false
}

/// True if `ident` appears anywhere in `text` as a whole token (not a
/// substring of a longer identifier).
fn contains_whole_ident(text: &str, ident: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let id: Vec<char> = ident.chars().collect();
    let (n, m) = (chars.len(), id.len());
    if m == 0 {
        return false;
    }
    let mut i = 0;
    while i + m <= n {
        if chars[i..i + m] == id[..] {
            let prev_ok = i == 0 || !is_ident_char(chars[i - 1]);
            let next_ok = i + m >= n || !is_ident_char(chars[i + m]);
            if prev_ok && next_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// True if the token starting at `start` (after skipping whitespace and an
/// optional opening paren of a cast we don't model) is the null pointer
/// constant `NULL` or `0`, terminated by a non-identifier/non-digit char.
fn rhs_is_null_constant(chars: &[char], start: usize) -> bool {
    let n = chars.len();
    let mut j = start;
    while j < n && chars[j].is_whitespace() {
        j += 1;
    }
    // `NULL`
    let null_kw = ['N', 'U', 'L', 'L'];
    if j + 4 <= n && chars[j..j + 4] == null_kw && (j + 4 >= n || !is_ident_char(chars[j + 4])) {
        return true;
    }
    // `0` (or `0L`, `0u`… ) — a bare zero literal, not `0x..`/`0.5`/`01`.
    if j < n && chars[j] == '0' {
        let after = if j + 1 < n { chars[j + 1] } else { ' ' };
        if !after.is_ascii_digit() && after != '.' && after != 'x' && after != 'X' {
            return true;
        }
    }
    false
}

/// True if identifier `ident` appears in `text` as the target of a whole-object
/// assignment: `ident =` or `(ident) =` (any number of wrapping parens),
/// excluding compound assignment (`+=`/`==`/…), field/element/deref writes, and
/// member/arrow access. See [`macro_output_param_indices`].
fn is_whole_assignment_target(text: &str, ident: &str) -> bool {
    find_assignment_targets(text, ident, |_| true)
}

/// True if `ident` appears in `text` as a whole-object assignment whose
/// right-hand side is the null pointer constant (`NULL` or `0`) — i.e.
/// `ident = NULL` / `(ident) = 0`. See [`macro_nulls_param_indices`].
fn is_null_assignment_target(text: &str, ident: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    find_assignment_targets(text, ident, |rhs_start| {
        rhs_is_null_constant(&chars, rhs_start)
    })
}

/// Scan `text` for whole-object assignment targets named `ident` (handling
/// wrapping parens and excluding deref/field/compound/comparison forms — see
/// [`is_whole_assignment_target`]). For each candidate, call `rhs_ok` with the
/// char index just past the `=`; return true on the first that passes.
fn find_assignment_targets(text: &str, ident: &str, rhs_ok: impl Fn(usize) -> bool) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let id: Vec<char> = ident.chars().collect();
    let (n, m) = (chars.len(), id.len());
    if m == 0 {
        return false;
    }
    let mut i = 0;
    while i + m <= n {
        if chars[i..i + m] == id[..] {
            // Whole-token match: boundaries must not be identifier chars.
            let prev_ok = i == 0 || !is_ident_char(chars[i - 1]);
            let next_ok = i + m >= n || !is_ident_char(chars[i + m]);
            // Look back past wrapping `(` and whitespace for the first
            // significant char. `*`/`.`/`->` there means a deref/field write
            // (`*(p) =`, `(*p) =`, `obj.ident`) which READS the identifier.
            let mut b = i;
            while b > 0 && (chars[b - 1].is_whitespace() || chars[b - 1] == '(') {
                b -= 1;
            }
            let prev_c = if b > 0 { chars[b - 1] } else { ' ' };
            let arrow = b >= 2 && chars[b - 1] == '>' && chars[b - 2] == '-';
            if prev_ok && next_ok && prev_c != '.' && prev_c != '*' && !arrow {
                // Skip whitespace and closing parens after the identifier.
                let mut j = i + m;
                while j < n && (chars[j].is_whitespace() || chars[j] == ')') {
                    j += 1;
                }
                // A single `=` (not `==`) immediately follows → assignment target.
                if j < n && chars[j] == '=' && (j + 1 >= n || chars[j + 1] != '=') && rhs_ok(j + 1)
                {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::CParser;

    fn table(src: &str) -> HashMap<String, FunctionMacro> {
        let mut p = CParser::new().unwrap();
        let (tree, src) = p.parse_source(src).unwrap();
        collect_function_macros(&tree.root_node(), &src)
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

    // ── Macro output-parameter detection ────────────────────────────────────

    #[test]
    fn output_param_simple_assignment() {
        // The first parameter is assigned; the others are only read.
        let t = table("#define SAVE(out, a, b) do { (out) = (a) + (b); } while(0)\n");
        assert_eq!(macro_output_param_indices(&t, "SAVE"), vec![0]);
    }

    #[test]
    fn output_param_cf_data_save_shape() {
        // curl's CF_DATA_SAVE pattern (with the nested CF_CTX_CALL_DATA macro
        // resolving through the table). save (arg 0) is assigned; cf/data are read.
        let t = table(
            "#define CF_CTX_CALL_DATA(cf) ((cf)->ctx->call_data)\n\
             #define CF_DATA_SAVE(save, cf, data) do { (save) = CF_CTX_CALL_DATA(cf); CF_CTX_CALL_DATA(cf).data = (data); } while(0)\n",
        );
        assert_eq!(macro_output_param_indices(&t, "CF_DATA_SAVE"), vec![0]);
    }

    #[test]
    fn output_param_excludes_field_and_deref_writes() {
        // Field write (p->f =), element write (p[i] =), and deref write (*p =)
        // all READ the pointer first — they are not whole-object outputs.
        let t = table(
            "#define FW(p) do { (p)->f = 1; } while(0)\n\
             #define EW(p) do { (p)[0] = 1; } while(0)\n\
             #define DW(p) do { *(p) = 1; } while(0)\n",
        );
        assert!(macro_output_param_indices(&t, "FW").is_empty());
        assert!(macro_output_param_indices(&t, "EW").is_empty());
        assert!(macro_output_param_indices(&t, "DW").is_empty());
    }

    #[test]
    fn output_param_excludes_compound_and_comparison() {
        // `+=` reads first; `==` is a comparison, not an assignment.
        let t = table(
            "#define ADDEQ(x, y) do { (x) += (y); } while(0)\n\
             #define CMP(x, y) ((x) == (y))\n",
        );
        assert!(macro_output_param_indices(&t, "ADDEQ").is_empty());
        assert!(macro_output_param_indices(&t, "CMP").is_empty());
    }

    #[test]
    fn output_param_multiple_outputs() {
        let t = table("#define BOTH(a, b, c) do { a = 1; b = 2; (void)c; } while(0)\n");
        assert_eq!(macro_output_param_indices(&t, "BOTH"), vec![0, 1]);
    }

    #[test]
    fn output_param_unknown_macro_is_empty() {
        let t = table("#define X(a) (a)\n");
        assert!(macro_output_param_indices(&t, "NOPE").is_empty());
    }

    // ── Macro write-through-pointer detection (EXP34-C/ARR00-C) ────────────

    #[test]
    fn writes_param_includes_field_and_deref_and_subscript() {
        // Unlike macro_output_param_indices, these ARE reported: writing
        // through the pointer proves it's non-null / in-bounds.
        let t = table(
            "#define FW(p) do { (p)->f = 1; } while(0)\n\
             #define EW(p) do { (p)[0] = 1; } while(0)\n\
             #define DW(p) do { *(p) = 1; } while(0)\n",
        );
        assert_eq!(macro_writes_param_indices(&t, "FW"), vec![0]);
        assert_eq!(macro_writes_param_indices(&t, "EW"), vec![0]);
        assert_eq!(macro_writes_param_indices(&t, "DW"), vec![0]);
    }

    #[test]
    fn writes_param_still_includes_whole_object_assignment() {
        let t = table("#define SAVE(out, a, b) do { (out) = (a) + (b); } while(0)\n");
        assert_eq!(macro_writes_param_indices(&t, "SAVE"), vec![0]);
    }

    #[test]
    fn writes_param_fts3_getvarint32_shape() {
        // sqlite's fts3GetVarint32(p, piVal): *piVal = *(u8*)(p) -- a deref
        // write to the second (output) parameter.
        let t = table("#define fts3GetVarint32(p, piVal) (*(piVal) = *(unsigned char*)(p))\n");
        assert_eq!(macro_writes_param_indices(&t, "fts3GetVarint32"), vec![1]);
    }

    #[test]
    fn writes_param_excludes_read_only_and_comparison() {
        let t = table(
            "#define READ(p) ((p)->f)\n\
             #define CMP(p) ((p)->f == 1)\n",
        );
        assert!(macro_writes_param_indices(&t, "READ").is_empty());
        assert!(macro_writes_param_indices(&t, "CMP").is_empty());
    }

    #[test]
    fn writes_param_unknown_macro_is_empty() {
        let t = table("#define X(a) (a)\n");
        assert!(macro_writes_param_indices(&t, "NOPE").is_empty());
    }

    // ── Free-and-null (safe-free) macro detection ───────────────────────────

    #[test]
    fn nulls_param_curl_safefree_shape() {
        // curl Curl_safefree expands free(ptr) then (ptr)=NULL through the
        // nested curlx_free wrapper.
        let t = table(
            "#define curlx_free(p) free(p)\n\
             #define Curl_safefree(ptr) do { curlx_free(ptr); (ptr) = NULL; } while(0)\n",
        );
        assert_eq!(macro_nulls_param_indices(&t, "Curl_safefree"), vec![0]);
    }

    #[test]
    fn nulls_param_zero_literal() {
        let t = table("#define SAFE_FREE(x) do { free(x); (x) = 0; } while(0)\n");
        assert_eq!(macro_nulls_param_indices(&t, "SAFE_FREE"), vec![0]);
    }

    #[test]
    fn nulls_param_excludes_plain_free_no_null() {
        // A free wrapper that does NOT null its arg must not be reported.
        let t = table("#define just_free(p) free(p)\n");
        assert!(macro_nulls_param_indices(&t, "just_free").is_empty());
    }

    #[test]
    fn nulls_param_excludes_nonzero_and_field_assign() {
        // RHS is not the null constant; and a field write is not whole-object.
        let t = table(
            "#define SETONE(x) do { (x) = 1; } while(0)\n\
             #define CLEARF(p) do { (p)->next = NULL; } while(0)\n",
        );
        assert!(macro_nulls_param_indices(&t, "SETONE").is_empty());
        assert!(macro_nulls_param_indices(&t, "CLEARF").is_empty());
    }

    #[test]
    fn nulls_param_only_nulled_arg() {
        // Frees a, nulls b — only b is the nulled param.
        let t = table("#define FN(a, b) do { free(a); (b) = NULL; } while(0)\n");
        assert_eq!(macro_nulls_param_indices(&t, "FN"), vec![1]);
    }

    // ── Case-label macro detection ──────────────────────────────────────────

    #[test]
    fn expands_to_case_label_sqlite_shape() {
        let t = table("#define CASE(i,str) case i: assert( strcmp(aSub[i].zName, str)==0 );\n");
        assert!(macro_expands_to_case_label(&t, "CASE"));
    }

    #[test]
    fn expands_to_case_label_rejects_non_case_body() {
        let t = table("#define FOO(i) do_something(i);\n");
        assert!(!macro_expands_to_case_label(&t, "FOO"));
    }

    #[test]
    fn expands_to_case_label_rejects_prefix_match() {
        // "casement(i)" must not be mistaken for the "case" keyword.
        let t = table("#define WEIRD(i) casement(i);\n");
        assert!(!macro_expands_to_case_label(&t, "WEIRD"));
    }

    #[test]
    fn expands_to_case_label_unknown_macro_is_false() {
        let t = table("#define X(a) (a)\n");
        assert!(!macro_expands_to_case_label(&t, "NOPE"));
    }

    // ── Deallocation (frees) macro detection ────────────────────────────────

    #[test]
    fn frees_param_simple_fclose_wrapper() {
        let t = table("#define SAFE_FCLOSE(f) fclose(f)\n");
        assert_eq!(macro_frees_param_indices(&t, "SAFE_FCLOSE"), vec![0]);
    }

    #[test]
    fn frees_param_safe_free_shape() {
        let t = table("#define SAFE_FREE(x) do { free(x); (x) = NULL; } while(0)\n");
        assert_eq!(macro_frees_param_indices(&t, "SAFE_FREE"), vec![0]);
    }

    #[test]
    fn frees_param_unrelated_macro_is_empty() {
        let t = table("#define MIN(x,y) (((x) < (y)) ? (x) : (y))\n");
        assert!(macro_frees_param_indices(&t, "MIN").is_empty());
    }

    #[test]
    fn forwarding_target_curl_rand_shape() {
        // curl's real (non-DEBUGBUILD) shape:
        // #define Curl_rand(a, b, c) Curl_rand_bytes(a, b, c)
        let t = table("#define Curl_rand(a, b, c) Curl_rand_bytes(a, b, c)\n");
        let (callee, map) = macro_forwarding_target(&t, "Curl_rand").expect("forwarding");
        assert_eq!(callee, "Curl_rand_bytes");
        assert_eq!(map, vec![Some(0), Some(1), Some(2)]);
    }

    #[test]
    fn forwarding_target_curl_rand_debug_shape_with_literal_and_cast() {
        // curl's DEBUGBUILD shape adds a literal arg and the real call site
        // wraps the buffer arg in a cast: Curl_rand(data, (unsigned char *)rnd, rnd_size)
        let t = table("#define Curl_rand(a, b, c) Curl_rand_bytes(a, TRUE, b, c)\n");
        let (callee, map) = macro_forwarding_target(&t, "Curl_rand").expect("forwarding");
        assert_eq!(callee, "Curl_rand_bytes");
        // arg0 -> macro param 0 (a), arg1 is the literal TRUE (no mapping),
        // arg2 -> macro param 1 (b), arg3 -> macro param 2 (c).
        assert_eq!(map, vec![Some(0), None, Some(1), Some(2)]);
    }

    #[test]
    fn forwarding_target_rejects_transformed_param() {
        // Not a pure passthrough: the callee sees `a+1`, not the bare param.
        let t = table("#define BUMP_CALL(a) real_fn(a+1)\n");
        let (callee, map) = macro_forwarding_target(&t, "BUMP_CALL").expect("forwarding");
        assert_eq!(callee, "real_fn");
        assert_eq!(map, vec![None]);
    }

    #[test]
    fn forwarding_target_none_for_non_call_body() {
        let t = table("#define MIN(x,y) (((x) < (y)) ? (x) : (y))\n");
        assert!(macro_forwarding_target(&t, "MIN").is_none());
    }

    #[test]
    fn forwarding_target_none_when_callee_is_itself_a_macro() {
        let t = table("#define INNER(a) real_fn(a)\n#define OUTER(a) INNER(a)\n");
        // OUTER expands (via rescan) all the way through INNER to real_fn, so
        // this should resolve straight to the real function, not stop at the
        // intermediate macro name.
        let (callee, map) = macro_forwarding_target(&t, "OUTER").expect("forwarding");
        assert_eq!(callee, "real_fn");
        assert_eq!(map, vec![Some(0)]);
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
        let (tree, src) = p.parse_source(src).unwrap();
        let ast_only = {
            let mut out = HashMap::new();
            collect_rec(&tree.root_node(), &src, &mut out);
            out
        };
        let merged = collect_function_macros(&tree.root_node(), &src);
        // Whatever the AST pass managed, the merged set must contain the wrapper.
        assert!(
            merged.contains_key("recovered_free"),
            "textual pass should recover recovered_free; ast_only={:?}",
            ast_only.keys().collect::<Vec<_>>()
        );
        assert_eq!(merged["recovered_free"].body, "free(ptr)");
    }

    #[test]
    fn alternatives_keep_every_preprocessor_branch_of_one_name() {
        // sqlite complete.c's shape, reduced: two mutually exclusive
        // definitions of one name, only the second of which touches a
        // caller-scope `c`.
        let src = "#ifdef SQLITE_ASCII\n                   #define IdChar(C)  ((sqlite3CtypeMap[(unsigned char)C]&0x46)!=0)\n                   #endif\n                   #ifdef SQLITE_EBCDIC\n                   #define IdChar(C)  (((c=C)>=0x42 && sqlite3IsEbcdicIdChar[c-0x40]))\n                   #endif\n";
        let alts = collect_function_macro_alternatives(src);
        let idchar = alts.get("IdChar").expect("IdChar collected");
        assert_eq!(idchar.len(), 2, "both branches kept: {:?}", idchar);

        // collect_function_macros keeps only the first, which is exactly why
        // the alternatives collector exists.
        assert!(!idchar
            .iter()
            .all(|m| macro_references_free_identifier(m, "c")));
        assert!(idchar
            .iter()
            .any(|m| macro_references_free_identifier(m, "c")));
    }

    #[test]
    fn free_identifier_check_ignores_parameters_and_substrings() {
        let alts = collect_function_macro_alternatives(
            "#define SQUARE(x) ((x) * (x))\n#define BUMP(n) (cnt += (n))\n",
        );
        let square = &alts["SQUARE"][0];
        let bump = &alts["BUMP"][0];

        // A macro's own parameter is bound by the macro, not by the caller.
        assert!(!macro_references_free_identifier(square, "x"));
        // Whole-token matching: `cnt` is free, but `c` and `nt` are not in it.
        assert!(macro_references_free_identifier(bump, "cnt"));
        assert!(!macro_references_free_identifier(bump, "c"));
        assert!(!macro_references_free_identifier(bump, "nt"));
        assert!(!macro_references_free_identifier(bump, ""));
    }
}
