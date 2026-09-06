//! Pre-parse pass: blank out empty (`#define NAME` with no body) object-like
//! macros throughout a file before it's fed to tree-sitter (task 435).
//!
//! tree-sitter-c's grammar doesn't recognize an unknown bare identifier
//! immediately preceding a declaration's type -- the WINAPI/RLAPI/APIENTRY
//! calling-convention/export-specifier idiom common in library headers with
//! shared-lib import/export guards, e.g.:
//! ```c
//! #ifndef RLAPI
//!     #define RLAPI       // Functions defined as 'extern' by default
//! #endif
//! RLAPI void rlPushMatrix(void);
//! ```
//! Once the parser hits one such declaration, error recovery can cascade far
//! enough to swallow unrelated content later in the file. Confirmed on
//! raylib's rlgl.h: the ERROR node starting at its `RLAPI`-guard block
//! propagated far enough that an unrelated `#ifndef`-guarded macro constant
//! defined hundreds of lines later never resolved either.
//!
//! Every occurrence of a confirmed-empty macro name (except its own
//! `#define` line, left untouched so the directive itself doesn't become a
//! new parse error) is replaced with same-length whitespace. This preserves
//! every byte offset in the file exactly, so all downstream line/column
//! positions stay correct, and no rule's logic depends on the semantic
//! content of a macro name that expands to nothing by definition.

use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

fn define_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*(.*)$").unwrap()
    })
}

/// True if `rest` (the text on a `#define NAME` line after the name) is
/// empty once a trailing `//` line comment or a single-line `/* ... */`
/// block comment is stripped. A name immediately followed by `(` (a
/// function-like macro's parameter list) is never "empty" here even with no
/// body, since `rest` still contains the parameter list text -- this
/// intentionally excludes function-like macros, which are a different
/// pattern (call-site invocations, not a bare identifier before a type).
fn is_empty_macro_body(rest: &str) -> bool {
    let mut text = rest;
    if let Some(idx) = text.find("//") {
        text = &text[..idx];
    }
    let text = text.trim();
    if text.is_empty() {
        return true;
    }
    // Single-line block comment covering the entire remainder.
    text.starts_with("/*") && text.ends_with("*/")
}

/// Scan `source` for `#define NAME` directives whose body is empty, per
/// [`is_empty_macro_body`]. Returns the macro names plus the byte ranges of
/// their own defining lines (kept untouched during blanking).
fn find_empty_object_macros(source: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    for m in define_line_re().captures_iter(source) {
        let name = &m[1];
        let rest = &m[2];
        if is_empty_macro_body(rest) {
            names.insert(name.to_string());
        }
    }
    names
}

/// Byte ranges of every line whose first non-whitespace character is `#`
/// (a preprocessor directive: `#define`, `#ifndef`, `#ifdef`, `#if`,
/// `#elif`, `#endif`, ...).
///
/// A header guard (`#define _MY_HEADER_H_` with an empty body, referenced
/// only in the matching `#ifndef _MY_HEADER_H_` / `#endif /* ... */` lines)
/// is *also* an "empty object macro" by the definition above, but its name
/// must never be blanked -- doing so broke DCL37-C's reserved-identifier
/// check on exactly this pattern in testing. Restricting blanking to
/// occurrences OUTSIDE any preprocessor directive line fixes that: a header
/// guard's only occurrences are on directive lines, so it never gets
/// touched, while an RLAPI-style export macro's problem occurrences are in
/// actual declaration code and still get blanked.
fn preproc_directive_line_ranges(source: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut pos = 0;
    // Threaded across lines: a directive continues onto the next physical
    // line via a trailing `\` (common for multi-line `#if`/`#elif`
    // conditions). Without tracking this, a continuation line like
    // `    !defined(GRAPHICS_API_OPENGL_11) && \` doesn't itself start with
    // `#`, so it read as ordinary code and had its macro names blanked --
    // corrupting the `#if` expression and producing a NEW parse error
    // exactly where this pass was supposed to remove one.
    let mut continuing = false;
    for line in source.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let is_directive = trimmed.starts_with('#') || continuing;
        if is_directive {
            ranges.push((pos, pos + line.len()));
        }
        let content = line.strip_suffix('\n').unwrap_or(line);
        let content = content.strip_suffix('\r').unwrap_or(content);
        continuing = is_directive && content.trim_end().ends_with('\\');
        pos += line.len();
    }
    ranges
}

/// Replace every whole-word occurrence of any name in `names` with spaces of
/// the same byte length, except on a preprocessor directive line.
fn blank_occurrences(source: &str, names: &HashSet<String>) -> String {
    if names.is_empty() {
        return source.to_string();
    }
    let directive_lines = preproc_directive_line_ranges(source);
    let mut out: Vec<u8> = source.as_bytes().to_vec();
    for name in names {
        let re = Regex::new(&format!(r"\b{}\b", regex::escape(name))).unwrap();
        for m in re.find_iter(source) {
            let (start, end) = (m.start(), m.end());
            let on_directive_line = directive_lines
                .iter()
                .any(|&(ls, le)| start >= ls && end <= le);
            if on_directive_line {
                continue;
            }
            for b in out.iter_mut().take(end).skip(start) {
                *b = b' ';
            }
        }
    }
    // Safe: we only ever replaced ASCII identifier-boundary bytes with
    // ASCII spaces, so any multi-byte UTF-8 sequences elsewhere are
    // untouched and the buffer remains valid UTF-8.
    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

/// Fallthrough-annotation macro names that are safe to blank even when this
/// file has no local `#define` for them at all, because their definition
/// lives in a header this pass never sees (task 461 category 8; sqlite's
/// `vdbe.c` uses `deliberate_fall_through` ~11 times but only `#define`s it
/// in `sqliteInt.h`, so [`find_empty_object_macros`] -- which only scans
/// this file's own text -- never finds it, and the bare identifier
/// immediately preceding a `case`/`default` label with no separating `;`
/// (the real, intended shape: `/* no break */ deliberate_fall_through` on
/// its own line) sends tree-sitter-c into ERROR recovery that invents a
/// bogus declaration whose declared name is literally `case`, tracked by
/// EXP33-C's init-state analysis as an uninitialized variable and flagged
/// wherever the real `case` keyword happens to reappear later in the same
/// (often huge, single-function) switch).
///
/// Safe unconditionally, not just when a local `#define` confirms it's
/// empty: `deliberate_fall_through` is sqlite's portable
/// fallthrough-annotation idiom (`sqliteInt.h` defines it as either nothing,
/// or `__attribute__((fallthrough));` -- a complete, self-terminated
/// statement -- depending on compiler support). Either expansion means the
/// real, preprocessed token stream never has a bare identifier directly
/// abutting a `case`/`default` label with no separator; this text shape
/// only arises here because aurora-lint has no preprocessor, so blanking it can
/// only ever recover structure, never remove something a rule could
/// otherwise have used (a fallthrough annotation carries no dataflow
/// meaning for EXP33-C either way).
const KNOWN_CROSS_FILE_EMPTY_MACROS: &[&str] = &["deliberate_fall_through"];

/// Blank every empty object-like macro's usages throughout `source`. See
/// module docs for why. Returns `source` unchanged if none are found.
pub fn blank_empty_object_macros(source: &str) -> String {
    let mut names = find_empty_object_macros(source);
    for &name in KNOWN_CROSS_FILE_EMPTY_MACROS {
        if source.contains(name) {
            names.insert(name.to_string());
        }
    }
    blank_occurrences(source, &names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blanks_empty_macro_before_declaration() {
        let src =
            "#ifndef RLAPI\n    #define RLAPI       // exported\n#endif\nRLAPI void f(void);\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out.len(), src.len());
        assert!(!out.contains("RLAPI void"));
        assert!(out.contains("     void f(void);"));
        // The #define line itself is left untouched.
        assert!(out.contains("#define RLAPI"));
    }

    #[test]
    fn leaves_non_empty_macros_alone() {
        let src = "#define MAX_SIZE 32\nint arr[MAX_SIZE];\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out, src);
    }

    #[test]
    fn leaves_function_like_macros_alone() {
        let src = "#define TRACELOG(level, ...) (void)0\nTRACELOG(1, \"x\");\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out, src);
    }

    #[test]
    fn function_like_macro_with_empty_body_not_blanked() {
        // `UNUSED(x)` is a call-site invocation elsewhere, not a bare
        // identifier before a declaration -- must not be blanked even
        // though its body is empty.
        let src = "#define UNUSED(x)\nvoid f(int y) { UNUSED(y); }\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out, src);
    }

    #[test]
    fn header_guard_macro_never_blanked() {
        // A header guard's name is technically also an "empty object
        // macro" (its #define has no body), but its only other occurrences
        // are on #ifndef/#endif directive lines -- must never be blanked,
        // or a reserved-identifier check on the guard name (DCL37-C) breaks.
        let src = "#ifndef _MY_HEADER_H_\n#define _MY_HEADER_H_\n\nint x;\n\n#endif /* _MY_HEADER_H_ */\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out, src);
    }

    #[test]
    fn blanks_known_cross_file_fallthrough_marker_with_no_local_define() {
        // No `#define deliberate_fall_through` anywhere in this source --
        // its definition lives in a header this pass never sees. Must still
        // be blanked so tree-sitter-c doesn't misparse the bare identifier
        // immediately preceding the `case` label (no separating `;`).
        let src = concat!(
            "static void f(int len, unsigned char *z, unsigned long long v) {\n",
            "  switch (len) {\n",
            "    default: z[1] = (unsigned char)v;\n",
            "             /* no break */ deliberate_fall_through\n",
            "    case 1:  z[0] = (unsigned char)v;\n",
            "  }\n",
            "}\n",
        );
        let out = blank_empty_object_macros(src);
        assert_eq!(out.len(), src.len());
        assert!(!out.contains("deliberate_fall_through"));
        assert!(out.contains("case 1:"));
    }

    #[test]
    fn leaves_source_alone_when_cross_file_marker_absent() {
        let src = "int x = 1;\nint y = 2;\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out, src);
    }

    #[test]
    fn preserves_byte_length_and_positions() {
        let src = "#define RLAPI\nRLAPI int x;\nint y = 1;\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out.len(), src.len());
        // Position of "int y = 1;" must be identical.
        let pos_orig = src.find("int y = 1;").unwrap();
        let pos_out = out.find("int y = 1;").unwrap();
        assert_eq!(pos_orig, pos_out);
    }
}
