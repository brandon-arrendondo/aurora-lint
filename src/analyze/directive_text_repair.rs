//! Pre-parse pass: respell two things in a preprocessing directive that
//! tree-sitter-c reads differently from the preprocessor, so the directive
//! keeps its extent.
//!
//! A `\` followed by blanks and then a line break is a line continuation
//! to GCC and Clang, which warn ("backslash and newline separated by space")
//! and splice; this crate's own directive lexer splices it too. The grammar
//! splices only a `\` right before the line break, so the directive ends on
//! that line and the rest of a continued `#define` or `#if` is parsed as
//! code at file scope. The `\` is moved to the end of its line and the
//! blanks go before it: the same continuation, now one the grammar reads.
//!
//! The grammar's `preproc_arg`, which holds a `#define`'s replacement list
//! and the operands of `#pragma`, `#error`, `#line` and the other
//! non-conditional directives, stops at the first `/*`, even inside a
//! string or character literal, and the rest is read as a comment that
//! never closes on that line. Each `/*` inside a literal of such a
//! directive keeps its `/` and has its `*` replaced with a space. That
//! changes one character of the literal in the repaired source, which
//! the rules and their messages read, and leaves its length alone; the
//! `/` stays, so a path prefix such as `"/tmp/"` reads the same. Only
//! suppressions read the original text. A directive the grammar parses
//! as an expression or a header name (`#if`, `#include`) has no
//! `preproc_arg` and is left as written.
//!
//! Both edits only move or replace bytes, so the length, the lines and
//! every directive's extent are unchanged.
//!
//! Known limits:
//! - A blank-separated continuation inside a string literal moves the
//!   blanks into the literal: `"ab\  ⏎cd"` reads as `"ab  \⏎cd"`, so
//!   the literal holds `"ab  cd"` where GCC gives `"abcd"`.
//! - A form feed or vertical tab between the `\` and the line break is
//!   not a blank here, though GCC splices it; `pp_tokens`' continuation
//!   reading agrees with this pass.
//! - Lines outside a directive are not repaired.

use std::borrow::Cow;

use crate::utility::cert_c::pp_tokens::{self, PpKind};

/// The directive's name, the identifier after its `#`.
fn directive_name(text: &str) -> &str {
    let rest = text[1..].trim_start_matches([' ', '\t']);
    let len = rest
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
        .count();
    &rest[..len]
}

/// Whether the grammar reads what follows the directive's name as
/// `preproc_arg` text: every directive but a conditional and a header
/// inclusion.
fn takes_preproc_arg(name: &str) -> bool {
    !matches!(
        name,
        "if" | "ifdef"
            | "ifndef"
            | "elif"
            | "elifdef"
            | "elifndef"
            | "else"
            | "endif"
            | "include"
            | "include_next"
            | "import"
    )
}

/// When the `\` at byte `i` of `b` starts a continuation with blanks between
/// it and the line break, the byte to move it to: the last one before the
/// line break (`\n`, or `\r\n`).
fn blank_continuation_target(b: &[u8], i: usize) -> Option<usize> {
    let mut k = i + 1;
    while k < b.len() && matches!(b[k], b' ' | b'\t' | b'\r') {
        k += 1;
    }
    if b.get(k) != Some(&b'\n') {
        return None;
    }
    let target = if b[k - 1] == b'\r' { k - 2 } else { k - 1 };
    (target > i).then_some(target)
}

/// The byte edits, as `(offset, new byte)` in the directive `text`, that
/// the module docs describe.
fn edits(text: &str) -> Vec<(usize, u8)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            if let Some(target) = blank_continuation_target(b, i) {
                let moved = if b[target] == b'\r' { b' ' } else { b[target] };
                out.push((i, moved));
                out.push((target, b'\\'));
                i = target + 1;
                continue;
            }
        }
        i += 1;
    }
    if takes_preproc_arg(directive_name(text)) && text.contains("/*") {
        for t in pp_tokens::lex_replacement_list(text, false) {
            if !matches!(t.kind, PpKind::StringLiteral | PpKind::CharLiteral) {
                continue;
            }
            for k in t.start..t.end.saturating_sub(1) {
                if b[k] == b'/' && b[k + 1] == b'*' {
                    out.push((k + 1, b' '));
                }
            }
        }
    }
    out
}

/// `source` with every directive respelled per the module docs. Length- and
/// line-preserving; borrowed when no directive needs it.
pub fn repair_directive_text(source: &str) -> Cow<'_, str> {
    let mut out: Option<Vec<u8>> = None;
    for start in pp_tokens::directive_starts(source) {
        let text = &source[start..];
        let end = pp_tokens::directive_end(text);
        let edits = edits(&text[..end]);
        if edits.is_empty() {
            continue;
        }
        let buf = out.get_or_insert_with(|| source.as_bytes().to_vec());
        for (at, byte) in edits {
            buf[start + at] = byte;
        }
    }
    match out {
        // Only ASCII bytes were moved or replaced with ASCII bytes.
        Some(buf) => Cow::Owned(String::from_utf8(buf).unwrap_or_else(|_| source.to_string())),
        None => Cow::Borrowed(source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::c_language;

    fn has_error(src: &str) -> bool {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&c_language()).unwrap();
        parser.parse(src, None).unwrap().root_node().has_error()
    }

    fn assert_repaired(src: &str) -> String {
        assert!(
            has_error(src),
            "the shape must break the raw parse: {src:?}"
        );
        let fixed = repair_directive_text(src).into_owned();
        assert_eq!(fixed.len(), src.len());
        assert_eq!(fixed.matches('\n').count(), src.matches('\n').count());
        assert!(!has_error(&fixed), "{fixed:?}");
        fixed
    }

    #[test]
    fn a_continuation_with_trailing_blanks_is_moved_to_the_line_end() {
        for src in [
            "#define B(x) do { \\  \n  x; \\\n} while (0)\nint z;\n",
            "#define B(x) do { \\\t\n  x; \\ \t \n} while (0)\nint z;\n",
            "#if A \\ \n  && B\nint y;\n#endif\n",
        ] {
            let fixed = assert_repaired(src);
            assert_eq!(fixed.matches('\\').count(), src.matches('\\').count());
            assert!(
                !fixed.contains("\\ ") && !fixed.contains("\\\t"),
                "{fixed:?}"
            );
        }
    }

    #[test]
    fn crlf_lines_keep_their_carriage_return() {
        let src = "#define B(x) do { \\ \r\n  x; \\\r\n} while (0)\r\nint z;\r\n";
        let fixed = assert_repaired(src);
        assert!(fixed.starts_with("#define B(x) do {  \\\r\n"), "{fixed:?}");
        assert_eq!(fixed.matches("\r\n").count(), src.matches("\r\n").count());
    }

    #[test]
    fn a_comment_opener_inside_a_literal_of_a_directive_is_respelled() {
        for src in [
            "#define MSG \"/* x\"\nint z;\n",
            "#define S \"a /* b */ c\"\nint z;\n",
            "#define C '/*'\nint z;\n",
            "#define E(x) do { puts(\"/* no\"); \\\n  x; \\\n} while (0)\nint z;\n",
            "#error \"no /* here\"\nint z;\n",
            "#pragma message(\"x /* y\")\nint z;\n",
        ] {
            let fixed = assert_repaired(src);
            assert!(!fixed.contains("/*"), "{fixed:?}");
            assert_eq!(
                fixed.matches('/').count(),
                src.matches('/').count(),
                "the `/` stays: {fixed:?}"
            );
        }
    }

    #[test]
    fn what_the_grammar_reads_is_left_as_written() {
        for src in [
            "#define U \"http://x/y\"\nint z;\n",
            "#define A(x) do { \\\n  x; \\\n} while (0)\nint z;\n",
            "#define A 1 /* c */\nint z;\n",
            "#include \"a/*b.h\"\n",
            "int f(void) { return puts(\"/* x\"); }\n",
            "char *p = \"a\\\\ \nb\";\n",
        ] {
            assert!(
                matches!(repair_directive_text(src), Cow::Borrowed(_)),
                "{src:?}"
            );
        }
    }

    /// With a real comment after the literal, this pass and the comment pass
    /// that runs after it repair the directive between them.
    #[test]
    fn a_literal_opener_before_a_real_comment_parses_with_the_comment_pass() {
        let src = "#define E(x) do { puts(\"/* no\"); /* c */ \\\n  x; \\  \n} while (0)\nint z;\n";
        assert!(has_error(src));
        let fixed = repair_directive_text(src);
        let fixed = crate::analyze::define_comment_blank::blank_define_body_comments(&fixed);
        assert_eq!(fixed.len(), src.len());
        assert!(fixed.contains("puts(\"/  no\");"), "{fixed:?}");
        assert!(!has_error(&fixed), "{fixed:?}");
    }

    /// An escaped backslash before the continuation is the literal's, and
    /// the `\` after it splices: only the last one moves.
    #[test]
    fn only_the_splicing_backslash_moves() {
        let src = "#define S \"a\\\\\\  \nb\"\nint z;\n";
        let fixed = repair_directive_text(src);
        assert_eq!(fixed, "#define S \"a\\\\  \\\nb\"\nint z;\n");
    }
}
