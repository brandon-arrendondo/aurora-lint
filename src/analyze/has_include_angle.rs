//! Pre-parse pass: spell `__has_include(<hdr.h>)` as `__has_include("hdr.h")`
//! on `#if`/`#elif` lines.
//!
//! tree-sitter-c parses a `#if` condition as a C expression, and
//! `<dlfcn.h>` is not one: the `<` and `>` read as relational operators
//! around a path, and the recovery does not stay on the directive line.
//! valkey's module.c has
//!
//! ```c
//! #if (defined(__GLIBC__) || ...) && __has_include(<dlfcn.h>)
//!     dlopen_flags |= RTLD_DEEPBIND;
//! #endif
//!
//!     handle = dlopen(path, dlopen_flags);
//! ```
//!
//! and the ERROR region the condition opens swallows the assignment below the
//! `#endif`, where EXP33-C read `handle` as a use before any write. Rules had
//! been patching the symptom one at a time on the directive line itself
//! (EXP13-C, INT33-C); the damage past it needs the parse fixed.
//!
//! The rewrite swaps each angle bracket for a double quote, so it preserves
//! length and every newline. The quoted form names the same header (the two
//! spellings differ only in search order, which a checker with no include
//! paths does not model) and parses as an ordinary string argument. A file
//! without the construct comes back byte-for-byte unchanged.

use std::borrow::Cow;

const OPERATORS: [&str; 2] = ["__has_include_next", "__has_include"];

/// Rewrite every `__has_include(<...>)` / `__has_include_next(<...>)` on a
/// `#if`/`#elif` logical line (backslash continuations included).
pub fn quote_has_include_headers(source: &str) -> Cow<'_, str> {
    if !source.contains("__has_include") {
        return Cow::Borrowed(source);
    }
    let mut out = source.as_bytes().to_vec();
    let mut changed = false;
    let mut in_condition = false;
    let mut line_start = 0;
    while line_start < source.len() {
        let line_end = source[line_start..]
            .find('\n')
            .map_or(source.len(), |i| line_start + i);
        let line = &source[line_start..line_end];
        if !in_condition {
            in_condition = is_conditional_directive(line);
        }
        if in_condition {
            changed |= quote_on_line(line, line_start, &mut out);
            in_condition = line.trim_end().ends_with('\\');
        }
        line_start = line_end + 1;
    }
    if !changed {
        return Cow::Borrowed(source);
    }
    // Only ASCII '<' and '>' were replaced with ASCII '"', so the bytes are
    // still valid UTF-8.
    Cow::Owned(String::from_utf8(out).expect("ASCII-for-ASCII substitution"))
}

/// `#if` or `#elif` (and `#elifdef`-less spellings with spaces after `#`).
fn is_conditional_directive(line: &str) -> bool {
    let Some(rest) = line.trim_start().strip_prefix('#') else {
        return false;
    };
    let word: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    word == "if" || word == "elif"
}

/// Quote the angle-bracketed operand of each operator occurrence on `line`,
/// writing into `out` at `offset`. True when anything changed.
fn quote_on_line(line: &str, offset: usize, out: &mut [u8]) -> bool {
    let mut changed = false;
    let mut search = 0;
    while let Some((at, op)) = next_operator(line, search) {
        search = at + op.len();
        let after = &line[search..];
        let Some(paren) = after.find(|c: char| !c.is_whitespace()) else {
            break;
        };
        if !after[paren..].starts_with('(') {
            continue;
        }
        let inner_start = search + paren + 1;
        let inner = &line[inner_start..];
        let Some(lt) = inner.find(|c: char| !c.is_whitespace()) else {
            break;
        };
        if !inner[lt..].starts_with('<') {
            continue;
        }
        let open = inner_start + lt;
        let Some(len) = line[open + 1..].find(['>', ')']) else {
            break;
        };
        let close = open + 1 + len;
        if line.as_bytes()[close] != b'>' {
            continue;
        }
        out[offset + open] = b'"';
        out[offset + close] = b'"';
        changed = true;
        search = close + 1;
    }
    changed
}

/// The next occurrence of an operator at or after `from`, as a whole word:
/// `__has_include_next` is not read as `__has_include` followed by `_next`.
fn next_operator(line: &str, from: usize) -> Option<(usize, &'static str)> {
    let mut best: Option<(usize, &'static str)> = None;
    for op in OPERATORS {
        let mut start = from;
        while let Some(i) = line[start..].find(op) {
            let at = start + i;
            let end = at + op.len();
            let before_ok = at == 0 || !is_ident_byte(line.as_bytes()[at - 1]);
            let after_ok = end >= line.len() || !is_ident_byte(line.as_bytes()[end]);
            if before_ok && after_ok {
                if best.is_none_or(|(b, _)| at < b) {
                    best = Some((at, op));
                }
                break;
            }
            start = end;
        }
    }
    best
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::quote_has_include_headers;

    #[test]
    fn quotes_the_header_on_an_if_line_only() {
        let src = "#if defined(X) && __has_include(<dlfcn.h>)\nint a = b < c > d;\n#endif\n";
        let out = quote_has_include_headers(src);
        assert_eq!(
            out,
            "#if defined(X) && __has_include(\"dlfcn.h\")\nint a = b < c > d;\n#endif\n"
        );
        assert_eq!(out.len(), src.len());
    }

    #[test]
    fn follows_continuations_and_elif_and_next() {
        let src = "#if A && \\\n    __has_include( <sys/x.h> )\n#elif __has_include_next(<y.h>)\n#endif\n";
        let out = quote_has_include_headers(src);
        assert_eq!(
            out,
            "#if A && \\\n    __has_include( \"sys/x.h\" )\n#elif __has_include_next(\"y.h\")\n#endif\n"
        );
    }

    #[test]
    fn leaves_other_text_alone() {
        // A quoted operand, a use outside a directive, and a longer name.
        let src = "#if __has_include(\"a.h\")\n#endif\nx = __has_include(<b.h>);\n#if my__has_include(<c.h>)\n#endif\n";
        assert_eq!(quote_has_include_headers(src), src);
    }
}
