//! Pre-parse pass: neutralize the embedded-JavaScript bodies of emscripten's
//! `EM_ASM`/`EM_JS` macros before the file reaches tree-sitter (task 1043).
//!
//! `EM_ASM(...)` and `EM_JS(...)` take a *JavaScript* body as a macro
//! argument. aurora-lint has no preprocessor, so that body is handed to the C
//! grammar as-is -- and a JS block is close enough to C that tree-sitter does
//! not isolate it into an `ERROR` node, it parses it into a perfectly
//! ordinary-looking `compound_statement` that every rule then walks:
//!
//! ```c
//! EM_JS(void, SetCanvasIdJs, (char *out, int outSize), {
//!     var canvasId = "#" + Module.canvas.id;
//!     stringToUTF8(canvasId, out, outSize);   // reads as a C call
//! });
//! ```
//!
//! DCL31-C is merely the loudest symptom (every JS call in reach becomes
//! "called without prior declaration"; on raylib's two web backends it even
//! reported the JS keyword `function` as a called function name, which no C
//! construct can produce). The body is visible to *all* rules, so this is a
//! whole-analyzer scoping fix rather than a per-rule exception.
//!
//! Two shapes, treated differently because they carry different amounts of
//! real C:
//!
//! * **`EM_ASM` family** -- the JavaScript is the FIRST macro argument and
//!   any arguments after it are ordinary C expressions bound into the JS as
//!   `$0`, `$1`, ... Only the first argument is blanked; the C arguments are
//!   left for the rules that care about them.
//! * **`EM_JS` family** -- `EM_JS(return_type, name, (params), { js })` is a
//!   function *definition*, so blanking the body alone would throw away a
//!   real declaration. The invocation is instead rewritten in place into the
//!   equivalent C declaration `return_type name (params);`, which both
//!   removes the JS and stops calls to the declared function reading as
//!   undeclared (raylib calls `SetCanvasIdJs`, `GetLastPastedText`,
//!   `GetLastPastedImage` and `RequestClipboardData` this way).
//!
//! Like the other pre-parse passes, every rewrite is byte-length- and
//! newline-preserving, so all downstream line/column positions are unchanged.
//! A blanked JS argument keeps a single `0` so the argument slot is still a
//! valid C expression rather than an empty one.

/// Macros whose FIRST argument is a JavaScript body; later arguments are C.
///
/// Covers the current spellings plus the deprecated `EM_ASM_`/`EM_ASM_ARGS`/
/// `*_V` ones, which are still in the wild. `EM_ASM_DEPS` is deliberately
/// absent: its arguments are C string literals, not a JS block.
const EM_ASM_MACROS: &[&str] = &[
    "EM_ASM",
    "EM_ASM_",
    "EM_ASM_ARGS",
    "EM_ASM_INT",
    "EM_ASM_INT_V",
    "EM_ASM_DOUBLE",
    "EM_ASM_DOUBLE_V",
    "EM_ASM_PTR",
    "MAIN_THREAD_EM_ASM",
    "MAIN_THREAD_EM_ASM_INT",
    "MAIN_THREAD_EM_ASM_DOUBLE",
    "MAIN_THREAD_EM_ASM_PTR",
    "MAIN_THREAD_ASYNC_EM_ASM",
];

/// Macros of the form `MACRO(return_type, name, (params), { js })`.
///
/// `EM_JS_DEPS` is deliberately absent: it declares a dependency list, not a
/// function, and its arguments are already valid C.
const EM_JS_MACROS: &[&str] = &["EM_JS", "EM_ASYNC_JS"];

/// If a comment, string literal or character literal starts at `i`, the byte
/// offset just past it; otherwise `None`.
///
/// JavaScript leans on both quote forms much harder than C does (`'i32'`,
/// `"image/"`, `'dual-rumble'`), and a `"https://..."` would otherwise look
/// like the start of a line comment, so every scan below goes through here
/// before it looks at a byte.
fn skip_literal_or_comment(b: &[u8], i: usize) -> Option<usize> {
    match b[i] {
        b'/' if b.get(i + 1) == Some(&b'/') => {
            let mut j = i + 2;
            while j < b.len() && b[j] != b'\n' {
                j += 1;
            }
            Some(j)
        }
        b'/' if b.get(i + 1) == Some(&b'*') => {
            let mut j = i + 2;
            while j + 1 < b.len() && !(b[j] == b'*' && b[j + 1] == b'/') {
                j += 1;
            }
            Some((j + 2).min(b.len()))
        }
        quote @ (b'"' | b'\'') => {
            let mut j = i + 1;
            while j < b.len() {
                match b[j] {
                    b'\\' => j += 2,
                    // An unterminated quote (an apostrophe in prose, say)
                    // must not swallow the rest of the file.
                    b'\n' => return Some(j),
                    c if c == quote => return Some(j + 1),
                    _ => j += 1,
                }
            }
            Some(b.len())
        }
        _ => None,
    }
}

/// First byte at or after `i` (and before `end`) that is neither whitespace
/// nor part of a comment.
fn skip_trivia(b: &[u8], mut i: usize, end: usize) -> usize {
    while i < end {
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b[i] == b'/' {
            if let Some(next) = skip_literal_or_comment(b, i) {
                i = next.min(end);
                continue;
            }
        }
        break;
    }
    i
}

/// Byte offset of the `)` matching the `(` at `open`.
fn matching_paren(b: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open;
    while i < b.len() {
        if let Some(next) = skip_literal_or_comment(b, i) {
            i = next;
            continue;
        }
        match b[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Offsets of the argument-separating commas in `start..end` -- those at
/// nesting depth zero with respect to `()`, `[]` and `{}`.
///
/// Braces count here even though the C preprocessor's own argument splitting
/// ignores them: this pass reads text, not a token stream, and a braced JS
/// block is exactly the case that must stay one argument.
fn top_level_commas(b: &[u8], start: usize, end: usize) -> Vec<usize> {
    let mut commas = Vec::new();
    let mut depth = 0i32;
    let mut i = start;
    while i < end {
        if let Some(next) = skip_literal_or_comment(b, i) {
            i = next;
            continue;
        }
        match b[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => commas.push(i),
            _ => {}
        }
        i += 1;
    }
    commas
}

/// Replace `start..end` with same-length whitespace, keeping newlines so the
/// line count is unchanged.
fn blank_range(out: &mut [u8], start: usize, end: usize) {
    for byte in out.iter_mut().take(end).skip(start) {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

/// [`blank_range`], but leaving a `0` at `start` so the blanked region is
/// still a valid C expression -- an argument slot cannot simply be empty.
/// `start` always points at a non-whitespace byte, so the `0` never lands on
/// a newline.
fn blank_to_zero(out: &mut [u8], start: usize, end: usize) {
    if start >= end {
        return;
    }
    blank_range(out, start, end);
    out[start] = b'0';
}

/// True if the byte at `start` sits on a preprocessor directive line, i.e.
/// the line's first non-whitespace character is `#`. The macros' own
/// `#define`s (and any `#ifdef EM_ASM`-style guard) are left alone.
fn on_directive_line(source: &str, start: usize) -> bool {
    let line_start = source[..start].rfind('\n').map_or(0, |nl| nl + 1);
    source[line_start..start].trim_start().starts_with('#')
}

/// Rewrite `MACRO(ret, name, (params), { js })` in place as the C
/// declaration `ret name (params);`. Returns false (leaving `out` untouched)
/// if the invocation does not have that exact shape, so the caller can fall
/// back to blanking the body alone.
fn rewrite_em_js_declaration(
    b: &[u8],
    out: &mut [u8],
    name_start: usize,
    open: usize,
    close: usize,
    commas: &[usize],
) -> bool {
    let [after_ret, after_name, after_params] = commas else {
        return false;
    };
    let params_start = skip_trivia(b, after_name + 1, *after_params);
    let body_start = skip_trivia(b, after_params + 1, close);
    if b.get(params_start) != Some(&b'(') || b.get(body_start) != Some(&b'{') {
        return false;
    }

    blank_range(out, name_start, open + 1); // the macro name and its `(`
    out[*after_ret] = b' ';
    out[*after_name] = b' ';
    out[*after_params] = b' ';
    blank_range(out, body_start, close); // the JavaScript body
    out[close] = b';';

    // The invocation's own `;`, now redundant, would be a stray null
    // statement at file scope.
    let mut trailing = close + 1;
    while matches!(b.get(trailing), Some(b' ' | b'\t')) {
        trailing += 1;
    }
    if b.get(trailing) == Some(&b';') {
        out[trailing] = b' ';
    }
    true
}

/// Blank every emscripten embedded-JavaScript macro body in `source`. See
/// the module docs for why. Returns `source` unchanged if it uses none.
pub fn blank_embedded_js(source: &str) -> String {
    if !EM_ASM_MACROS
        .iter()
        .chain(EM_JS_MACROS)
        .any(|name| source.contains(name))
    {
        return source.to_string();
    }
    let b = source.as_bytes();
    let mut out = b.to_vec();

    let mut i = 0usize;
    while i < b.len() {
        if let Some(next) = skip_literal_or_comment(b, i) {
            i = next;
            continue;
        }
        if !(b[i].is_ascii_alphanumeric() || b[i] == b'_') {
            i += 1;
            continue;
        }
        // Consume the whole identifier (or number) so a later iteration can
        // never re-enter one partway through.
        let name_start = i;
        while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
            i += 1;
        }
        let name = &source[name_start..i];
        let is_em_asm = EM_ASM_MACROS.contains(&name);
        let is_em_js = EM_JS_MACROS.contains(&name);
        if (!is_em_asm && !is_em_js) || on_directive_line(source, name_start) {
            continue;
        }

        let open = skip_trivia(b, i, b.len());
        if b.get(open) != Some(&b'(') {
            continue;
        }
        let Some(close) = matching_paren(b, open) else {
            continue;
        };
        let commas = top_level_commas(b, open + 1, close);

        if is_em_js && rewrite_em_js_declaration(b, &mut out, name_start, open, close, &commas) {
            i = close + 1;
            continue;
        }

        // The JS body is the first argument for `EM_ASM`, and the last one
        // for an `EM_JS` that did not match the declaration shape above.
        let (body_start, body_end) = if is_em_asm {
            (open + 1, commas.first().copied().unwrap_or(close))
        } else {
            (commas.last().map_or(open + 1, |c| c + 1), close)
        };
        let body_start = skip_trivia(b, body_start, body_end);
        blank_to_zero(&mut out, body_start, body_end);
        i = close + 1;
    }

    // Safe: every byte written is ASCII (`' '`, `'0'` or `';'`) and every
    // range replaced is delimited by ASCII, so multi-byte sequences are
    // either wholly overwritten or wholly untouched.
    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every rewrite must keep byte offsets and line numbers exactly, since
    /// the whole pipeline reports positions against the repaired text.
    fn assert_shape_preserved(src: &str, out: &str) {
        assert_eq!(src.len(), out.len(), "byte length changed");
        assert_eq!(
            src.matches('\n').count(),
            out.matches('\n').count(),
            "line count changed"
        );
    }

    #[test]
    fn em_js_becomes_a_c_declaration() {
        let src = "EM_JS(void, SetCanvasIdJs, (char *out, int outSize), {\n\
                   \x20   var canvasId = \"#\" + Module.canvas.id;\n\
                   \x20   stringToUTF8(canvasId, out, outSize);\n\
                   });\n";
        let out = blank_embedded_js(src);
        assert_shape_preserved(src, &out);
        // The closing `)` becomes the declaration's `;`, so it lands where
        // the macro invocation ended; the invocation's own `;` is dropped.
        assert_eq!(
            out.lines().next().unwrap().trim_end(),
            "      void  SetCanvasIdJs  (char *out, int outSize)"
        );
        assert!(!out.contains("stringToUTF8"));
        assert_eq!(out.matches(';').count(), 1);
    }

    #[test]
    fn em_async_js_becomes_a_c_declaration() {
        let src = "EM_ASYNC_JS(void, RequestClipboardData, (void), {\n\
                   \x20   let items = await navigator.clipboard.read();\n\
                   });\n";
        let out = blank_embedded_js(src);
        assert_shape_preserved(src, &out);
        assert_eq!(
            out.lines().next().unwrap().trim_end(),
            "            void  RequestClipboardData  (void)"
        );
        assert_eq!(out.matches(';').count(), 1);
        assert!(!out.contains("navigator"));
    }

    #[test]
    fn em_asm_blanks_the_js_but_keeps_the_c_arguments() {
        let src =
            "void f(void) {\n    EM_ASM({ Module.canvas.style.width = $0; }, width*dpr);\n}\n";
        let out = blank_embedded_js(src);
        assert_shape_preserved(src, &out);
        assert!(out.contains("EM_ASM(0"), "{out:?}");
        assert!(out.contains(", width*dpr);"), "{out:?}");
        assert!(!out.contains("Module"));
    }

    #[test]
    fn em_asm_blanks_an_unbraced_body() {
        let src = "void f(void) {\n    EM_ASM(document.exitFullscreen(););\n}\n";
        let out = blank_embedded_js(src);
        assert_shape_preserved(src, &out);
        assert!(out.contains("EM_ASM(0"), "{out:?}");
        assert!(!out.contains("exitFullscreen"));
    }

    #[test]
    fn em_asm_body_may_open_on_the_next_line() {
        let src = "void f(void) {\n    EM_ASM\n    (\n        setTimeout(function() { x(); }, 100);\n    );\n}\n";
        let out = blank_embedded_js(src);
        assert_shape_preserved(src, &out);
        assert!(!out.contains("setTimeout"));
        assert!(!out.contains("function"));
    }

    /// A top-level comma inside the JS block must not end the body -- the
    /// brace nesting is what separates JS from the trailing C arguments.
    #[test]
    fn braced_body_may_contain_commas() {
        let src = "void f(void) {\n    EM_ASM({ g({ a: 0, b: $1 }); }, x, y);\n}\n";
        let out = blank_embedded_js(src);
        assert_shape_preserved(src, &out);
        assert!(out.contains(", x, y);"), "{out:?}");
        assert!(!out.contains("a: 0"));
    }

    /// JS quotes and `//` inside a string must not derail the scan.
    #[test]
    fn js_strings_are_scanned_as_literals() {
        let src = "void f(void) {\n    EM_ASM({ open(\"https://x/\"); setValue(p, 'i32'); }, p);\n    int after = 1;\n}\n";
        let out = blank_embedded_js(src);
        assert_shape_preserved(src, &out);
        assert!(out.contains(", p);"), "{out:?}");
        assert!(out.contains("int after = 1;"), "{out:?}");
        assert!(!out.contains("setValue"));
    }

    #[test]
    fn the_macros_own_define_is_left_alone() {
        let src = "#define EM_ASM(code, ...) emscripten_asm_const_int(#code)\n";
        assert_eq!(blank_embedded_js(src), src);
    }

    /// `EM_ASM_DEPS`/`EM_JS_DEPS` take C string literals, not a JS block.
    #[test]
    fn dependency_list_macros_are_left_alone() {
        let src = "EM_JS_DEPS(deps, \"$stringToUTF8\");\nEM_ASM_DEPS(more, \"$UTF8ToString\");\n";
        assert_eq!(blank_embedded_js(src), src);
    }

    #[test]
    fn a_file_with_no_embedded_js_is_untouched() {
        let src = "int main(void) { return 0; }\n";
        assert_eq!(blank_embedded_js(src), src);
    }

    /// An `EM_JS` that is not the four-argument definition shape still has
    /// its trailing JS blanked, it just stays a call expression.
    #[test]
    fn unexpected_em_js_shape_falls_back_to_blanking_the_body() {
        let src = "EM_JS(void, name, { stringToUTF8(a); });\n";
        let out = blank_embedded_js(src);
        assert_shape_preserved(src, &out);
        assert!(!out.contains("stringToUTF8"));
        assert!(out.starts_with("EM_JS(void, name, 0"), "{out:?}");
    }
}
