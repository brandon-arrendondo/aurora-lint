//! Pre-parse pass: blank out empty (`#define NAME` with no body) object-like
//! macros throughout a file before it's fed to tree-sitter (task 435), and
//! substitute qualifier-alias macros (`#define CONST const`) with the
//! keyword they expand to (task 758).
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
//!
//! A qualifier-alias macro is the same class of hazard from the other side:
//! Tcl's `#define CONST const` (sqlite's `src/tclsqlite.h:37`) means the
//! standard Tcl callback signature is written `Tcl_Obj *CONST objv[]`.
//! Without a preprocessor tree-sitter-c cannot know `CONST` is a qualifier;
//! it reads it as the DECLARATOR NAME, so every declarator-reading rule
//! (DCL13-C's `is_const`, DCL31-C's function-name extraction, ...) sees a
//! phantom parameter named `CONST` and misses the real one. Substituting
//! the name with the keyword text, padded with trailing spaces to preserve
//! byte length, feeds tree-sitter a token stream it parses correctly and
//! whose `type_qualifier` node reads back as the literal keyword every rule
//! already checks for.

use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// Type qualifiers we substitute a matching macro alias with. Only keywords
/// tree-sitter-c parses as `type_qualifier`; storage-class specifiers
/// (`static`, `inline`) and attribute prefixes (`__attribute__`) are a
/// different parser hazard and not covered here.
const QUALIFIER_KEYWORDS: &[&str] = &["const", "volatile", "restrict", "_Atomic"];

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
/// the same byte length, except on a preprocessor directive line. A blanked
/// name that stood alone as a statement takes its terminating `;` with it --
/// see [`terminating_semicolon_to_blank`].
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
            if let Some(semi) = terminating_semicolon_to_blank(source, start, end, &directive_lines)
            {
                out[semi] = b' ';
            }
        }
    }
    // Safe: we only ever replaced ASCII identifier-boundary bytes with
    // ASCII spaces, so any multi-byte UTF-8 sequences elsewhere are
    // untouched and the buffer remains valid UTF-8.
    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

/// Byte offset of the `;` that terminates a bare `NAME;` statement whose
/// `NAME` (spanning `start..end`) has just been blanked to nothing, or None
/// if that `;` must stay.
///
/// The name expands to nothing, so post-preprocessor the statement *is*
/// nothing, and leaving the `;` behind hands every downstream rule a null
/// statement the programmer never wrote. MSC12-C reported exactly that as
/// "Stray semicolon has no effect" on sqlite's `wsdStatInit;`,
/// `wsdAutoextInit;`, `wsdHooksInit;` and `deliberate_fall_through;` --
/// advice to delete a line that does not exist (task 1006).
///
/// Two things have to hold. The macro must be the first token on its line,
/// which is what separates a statement of its own from a trailing decorator
/// on the construct above it: curl's `} PACK;` closes a `struct` and its `;`
/// is mandatory, whereas sqlite's `wsdStatInit;` and
/// `deliberate_fall_through;` each occupy a line. And the preceding
/// significant character must be `;`, `{` or `}`, so the macro began a fresh
/// statement in a statement list where a null statement is optional. After
/// anything else the `;` may be the *required* body of an `if`, `else`,
/// `while` or `for`, or the statement a label must be followed by
/// (`if (x) EMPTY;`, `label: EMPTY;`), and blanking it would turn a clean
/// parse into an error -- the opposite of what this pass exists for. So a
/// preceding `)` or `:` keeps it.
///
/// Preprocessor directive lines are skipped on the way back rather than
/// treated as code: sqlite's `wsdAutoextInit;` sits directly under an
/// `#endif`, and it is the real code above that decides whether a null
/// statement is optional there. `if (x)` followed by an `#ifdef` and then
/// the macro still reads as `)`, so it keeps its `;`.
fn terminating_semicolon_to_blank(
    source: &str,
    start: usize,
    end: usize,
    directive_lines: &[(usize, usize)],
) -> Option<usize> {
    let bytes = source.as_bytes();

    // The macro must open its own line -- a decorator sharing a line with
    // the construct it decorates (`} PACK;`) owns no statement, and its `;`
    // belongs to that construct.
    if source[..start]
        .rsplit('\n')
        .next()
        .is_some_and(|head| !head.trim().is_empty())
    {
        return None;
    }

    // Forward: only whitespace may sit between the name and its `;`.
    let mut i = end;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    if bytes.get(i) != Some(&b';') {
        return None;
    }

    // Backward to the last significant character, skipping whitespace and
    // whole block comments.
    let mut j = start;
    loop {
        while j > 0 && bytes[j - 1].is_ascii_whitespace() {
            j -= 1;
        }
        if j >= 2 && &source[j - 2..j] == "*/" {
            match source[..j - 2].rfind("/*") {
                Some(open) => {
                    j = open;
                    continue;
                }
                None => return None,
            }
        }
        if let Some(&(ls, _)) = directive_lines
            .iter()
            .find(|&&(ls, le)| j > ls && j - 1 < le)
        {
            if ls == 0 {
                return Some(i);
            }
            j = ls;
            continue;
        }
        break;
    }
    // Start of file: a bare macro statement there is not inside any control
    // structure, so the `;` is optional.
    let Some(&prev) = bytes.get(j.wrapping_sub(1)).filter(|_| j > 0) else {
        return Some(i);
    };
    matches!(prev, b';' | b'{' | b'}').then_some(i)
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
    let aliased = substitute_qualifier_alias_macros(source);
    let mut names = find_empty_object_macros(&aliased);
    for &name in KNOWN_CROSS_FILE_EMPTY_MACROS {
        if aliased.contains(name) {
            names.insert(name.to_string());
        }
    }
    blank_occurrences(&aliased, &names)
}

/// Scan `source` for `#define NAME <qualifier>` directives where the body
/// is a single type-qualifier keyword. Returns the mapping from macro name
/// to the keyword it expands to, restricted to names at least as long as
/// the keyword (so the substitution can preserve byte length by trailing
/// with spaces). Names shorter than their keyword are silently skipped --
/// the byte-length invariant is more important than covering that
/// (uncommon) case.
fn find_qualifier_alias_macros(source: &str) -> HashMap<String, &'static str> {
    let mut aliases = HashMap::new();
    for m in define_line_re().captures_iter(source) {
        let name = &m[1];
        let body = m[2].trim();
        // Strip a trailing line-comment: `#define CONST const  // Tcl compat`.
        let body = body.split("//").next().unwrap_or(body).trim();
        // Strip a single-line block-comment tail: `... /* compat */`.
        let body = if let Some(idx) = body.rfind("/*") {
            if body[idx..].ends_with("*/") {
                body[..idx].trim()
            } else {
                body
            }
        } else {
            body
        };
        for kw in QUALIFIER_KEYWORDS {
            if body == *kw && name.len() >= kw.len() {
                aliases.insert(name.to_string(), *kw);
                break;
            }
        }
    }
    aliases
}

/// Replace every whole-word occurrence of a qualifier-alias macro NAME
/// (outside a preprocessor directive line) with `keyword` followed by
/// enough trailing spaces to preserve the NAME's byte length. This makes
/// tree-sitter-c parse the qualifier as if it had been spelled literally,
/// so declarator-reading rules see the real parameter name and the
/// keyword as a `type_qualifier` node (task 758).
fn substitute_qualifier_alias_macros(source: &str) -> String {
    let aliases = find_qualifier_alias_macros(source);
    if aliases.is_empty() {
        return source.to_string();
    }
    let directive_lines = preproc_directive_line_ranges(source);
    let mut out: Vec<u8> = source.as_bytes().to_vec();
    for (name, keyword) in &aliases {
        let re = Regex::new(&format!(r"\b{}\b", regex::escape(name))).unwrap();
        for m in re.find_iter(source) {
            let (start, end) = (m.start(), m.end());
            let on_directive_line = directive_lines
                .iter()
                .any(|&(ls, le)| start >= ls && end <= le);
            if on_directive_line {
                continue;
            }
            let kw_bytes = keyword.as_bytes();
            for (i, b) in out.iter_mut().enumerate().take(end).skip(start) {
                *b = if i - start < kw_bytes.len() {
                    kw_bytes[i - start]
                } else {
                    b' '
                };
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
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
    fn blanks_the_semicolon_of_a_bare_macro_statement() {
        // `wsdStatInit;` expands to nothing, so leaving the `;` behind hands
        // every rule a null statement the programmer never wrote (task 1006).
        let src = "#define wsdStatInit\nint f(void){\n  wsdStatInit;\n  return 1;\n}\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out.len(), src.len());
        assert!(out.contains("\n              \n"), "got {:?}", out);
    }

    #[test]
    fn blanks_the_semicolon_across_an_intervening_directive_line() {
        // sqlite's `wsdAutoextInit;` sits directly under an `#endif`; the
        // real code above it is what decides whether the `;` is optional.
        let src = "#define wsdAutoextInit\nint f(void){\n#endif\n  wsdAutoextInit;\n}\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out.len(), src.len());
        assert!(out.contains("\n                 \n"), "got {:?}", out);
    }

    #[test]
    fn keeps_the_semicolon_of_a_trailing_decorator_macro() {
        // curl's `} PACK;` closes a struct: that `;` is mandatory, and
        // blanking it broke smb.c's parse badly enough to add 62 findings in
        // other rules (task 1006).
        let src = "#define PACK\nstruct s {\n  int x;\n} PACK;\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out.len(), src.len());
        assert!(out.contains("}     ;"), "got {:?}", out);
    }

    #[test]
    fn keeps_the_semicolon_when_it_is_a_required_statement() {
        // `if (x) EMPTY;` needs the null statement -- blanking it turns a
        // clean parse into an error.
        let src = "#define EMPTY\nvoid f(int x){\n  if (x) EMPTY;\n}\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out.len(), src.len());
        assert!(out.contains("if (x)      ;"), "got {:?}", out);
    }

    #[test]
    fn keeps_the_semicolon_of_a_line_starting_required_statement() {
        // Line-start is satisfied here, so the preceding `)` is what has to
        // keep the `;`: it is the `if`'s body.
        let src = "#define EMPTY\nvoid f(int x){\n  if (x)\n    EMPTY;\n}\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out.len(), src.len());
        assert!(out.contains("\n         ;\n"), "got {:?}", out);
    }

    #[test]
    fn keeps_the_semicolon_after_a_label() {
        let src = "#define EMPTY\nvoid f(void){\n  done: EMPTY;\n}\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out.len(), src.len());
        assert!(out.contains("done:      ;"), "got {:?}", out);
    }

    #[test]
    fn leaves_a_macro_used_as_a_value_and_its_semicolon_alone() {
        // Not a bare statement: the `;` terminates a real assignment.
        let src = "#define EMPTY\nvoid f(int *p){\n  *p = 1 EMPTY;\n}\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out.len(), src.len());
        assert!(out.contains("*p = 1      ;"), "got {:?}", out);
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
    fn substitutes_qualifier_alias_macro_at_declarator_position() {
        // Tcl's `#define CONST const` (sqlite src/tclsqlite.h:37). Every
        // declarator-reading rule reads `Tcl_Obj *CONST objv[]` as a
        // parameter literally named CONST, since tree-sitter-c cannot know
        // CONST is a qualifier without a preprocessor (task 758).
        let src = "#define CONST const\nint f(int *CONST p);\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out.len(), src.len());
        assert!(out.contains("int f(int *const p);"), "got {:?}", out);
        // The #define line itself is left untouched.
        assert!(out.contains("#define CONST const\n"));
    }

    #[test]
    fn pads_longer_qualifier_alias_name_with_trailing_spaces() {
        // `_CONST` (6 chars) -> `const ` (keyword + one trailing space),
        // preserving byte length.
        let src = "#define _CONST const\nint f(int *_CONST p);\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out.len(), src.len());
        assert!(out.contains("int f(int *const  p);"), "got {:?}", out);
    }

    #[test]
    fn handles_multiple_qualifier_aliases() {
        let src = "#define CONST const\n#define VOLATILE volatile\nint f(int *CONST p, int *VOLATILE q);\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out.len(), src.len());
        assert!(
            out.contains("int f(int *const p, int *volatile q);"),
            "got {:?}",
            out
        );
    }

    #[test]
    fn qualifier_alias_shorter_than_keyword_not_substituted() {
        // `_A` is 2 chars, `const` is 5 -- cannot preserve byte length,
        // skip.
        let src = "#define _A const\nint f(int *_A p);\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out, src);
    }

    #[test]
    fn qualifier_alias_left_alone_on_directive_lines() {
        // The name may appear on `#ifdef CONST` / `#undef CONST` etc. --
        // must not be substituted there, or the directive syntax breaks.
        let src = "#define CONST const\n#ifdef CONST\nint x;\n#endif\nint f(int *CONST p);\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out.len(), src.len());
        assert!(out.contains("#ifdef CONST\n"), "got {:?}", out);
        assert!(out.contains("int f(int *const p);"), "got {:?}", out);
    }

    #[test]
    fn substitution_ignores_trailing_comment_on_define() {
        let src = "#define CONST const  /* Tcl compat */\nint f(int *CONST p);\n";
        let out = blank_empty_object_macros(src);
        assert_eq!(out.len(), src.len());
        assert!(out.contains("int f(int *const p);"), "got {:?}", out);
    }

    #[test]
    fn non_qualifier_body_not_substituted() {
        // Body isn't one of the recognised qualifier keywords.
        let src = "#define MAX 100\nint arr[MAX];\n";
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
