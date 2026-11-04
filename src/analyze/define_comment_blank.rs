//! Pre-parse pass: blank the comments inside a `#define` that a line
//! continuation follows.
//!
//! tree-sitter-c reads a macro's replacement list as one `preproc_arg`
//! token that stops at a comment. When a `\` continuation follows the
//! comment, the parser does not take the continued lines back into the
//! directive: the `#define` ends in an `ERROR` and the rest of the body is
//! read as code at file scope. A statement-like body (mbedtls `ecdsa.c`'s
//! `ECDSA_RS_ENTER(SUB)`, a `do { ... } while (0)` with a comment on its
//! first continued line) then leaves `if`, `return` and a `##` paste at
//! file scope, and once the other repairs have run the whole file can end
//! up inside one top-level `ERROR`. A block comment with no continuation
//! after it (one on the last line, or one right after the parameters, which
//! the grammar reads before the `preproc_arg` starts) and a `//` comment
//! parse cleanly, and a directive with only those is left as written, as
//! is one whose block comment ends the replacement list, a `\` inside it
//! continuing nothing but the comment. In one that needs the repair, every
//! comment is blanked.
//!
//! The preprocessor replaces every comment with a space before it reads
//! the directive (C11 5.1.1.2 phase 3), so blanking one to spaces keeps
//! what the macro defines. Each comment byte becomes a space; every `\`
//! that splices a line, and the line break after it, stays, so the length,
//! the lines and the directive's extent are unchanged. A block comment that
//! breaks a line without a `\` is a line break the directive only spans
//! because the comment hides it; blanking would end the directive there,
//! so such a `#define` is left as written.

use std::borrow::Cow;

use crate::utility::cert_c::pp_tokens;

/// Whether the directive at `text` (starting at its `#`) is a `#define`.
fn is_define(text: &str) -> bool {
    let rest = text[1..].trim_start_matches([' ', '\t']);
    rest.strip_prefix("define").is_some_and(|after| {
        after
            .bytes()
            .next()
            .is_none_or(|b| !(b.is_ascii_alphanumeric() || b == b'_'))
    })
}

/// Length of the line continuation (`\`, optional blanks, line break) at
/// byte `i` of `b`, or 0 when there is none.
fn continuation_len(b: &[u8], i: usize) -> usize {
    if b[i] != b'\\' {
        return 0;
    }
    let mut k = i + 1;
    while k < b.len() && matches!(b[k], b' ' | b'\t' | b'\r') {
        k += 1;
    }
    if b.get(k) == Some(&b'\n') {
        k + 1 - i
    } else {
        0
    }
}

/// The comment bytes of the directive `text`, as positions to blank, when
/// a block comment in it is followed by a line continuation and every line
/// break outside its tokens is spliced. Only a block comment inside the
/// replacement list counts: a `//` comment, or one before the list's first
/// token, parses as it should. `None` when there is nothing to do or it is
/// not safe.
fn comment_bytes(text: &str) -> Option<Vec<usize>> {
    let b = text.as_bytes();
    let tokens = pp_tokens::lex_replacement_list(text, false);
    let mut gaps = Vec::with_capacity(tokens.len() + 1);
    let mut at = 0;
    for t in &tokens {
        gaps.push(at..t.start);
        at = t.end;
    }
    gaps.push(at..b.len());
    // tokens: `#`, `define`, the name, then (no space before the `(`) a
    // function-like macro's parameter list. A comment before the first
    // token after those precedes the `preproc_arg` and parses as it should.
    let mut body = 3;
    if tokens
        .get(3)
        .is_some_and(|t| t.is("(") && t.start == tokens[2].end)
    {
        body = tokens.iter().position(|t| t.is(")"))? + 1;
    }
    let body_start = tokens.get(body)?.start;

    let mut comment = Vec::new();
    let mut first_block_comment = None;
    let mut last_continuation = None;
    for gap in gaps {
        let mut i = gap.start;
        while i < gap.end {
            let spliced = continuation_len(b, i);
            if spliced > 0 {
                last_continuation = Some(i);
                i += spliced;
                continue;
            }
            match b[i] {
                b'\n' => return None,
                b' ' | b'\t' | b'\r' => {}
                _ => {
                    if b[i] == b'/'
                        && b.get(i + 1) == Some(&b'*')
                        && i > body_start
                        && first_block_comment.is_none()
                    {
                        first_block_comment = Some(i);
                    }
                    comment.push(i);
                }
            }
            i += 1;
        }
    }
    // Only a comment with replacement-list tokens after it cuts anything
    // off: one closing the list (a `\` inside it continuing only the
    // comment) leaves nothing for the parser to lose.
    let first_block_comment = first_block_comment?;
    (last_continuation? > first_block_comment
        && tokens.iter().any(|t| t.start > first_block_comment))
    .then_some(comment)
}

/// `source` with the comments of every `#define` that a continuation
/// follows blanked to spaces, per the module docs. Length- and
/// line-preserving; borrowed when no directive needs it.
pub fn blank_define_body_comments(source: &str) -> Cow<'_, str> {
    let mut out: Option<Vec<u8>> = None;
    for start in pp_tokens::directive_starts(source) {
        let text = &source[start..];
        if !is_define(text) {
            continue;
        }
        let end = pp_tokens::directive_end(text);
        let Some(bytes) = comment_bytes(&text[..end]) else {
            continue;
        };
        let buf = out.get_or_insert_with(|| source.as_bytes().to_vec());
        for i in bytes {
            buf[start + i] = b' ';
        }
    }
    match out {
        // Only bytes of comments were replaced, each with an ASCII space;
        // a multi-byte character in a comment becomes as many spaces.
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

    #[test]
    fn a_comment_before_a_continuation_is_blanked_and_the_define_parses() {
        for src in [
            "#define A(x) do { \\\n  /* c */ \\\n  foo(); \\\n} while (0)\nint z;\n",
            "#define A(x) do { \\\n  foo(); /* c */ \\\n  bar(); \\\n} while (0)\nint z;\n",
            "#define A(x) do { /* c */ \\\n  foo(); \\\n} while (0)\nint z;\n",
            "#define A(x) do { \\\n  foo(); /* a \\\n b */ \\\n} while (0)\nint z;\n",
            "  #  define A 1 /* c */ \\\n  + 2\nint z;\n",
        ] {
            assert!(
                has_error(src),
                "the shape must break the raw parse: {src:?}"
            );
            let fixed = blank_define_body_comments(src);
            assert_eq!(fixed.len(), src.len());
            assert_eq!(fixed.matches('\n').count(), src.matches('\n').count());
            assert!(!fixed.contains("/*"), "{fixed:?}");
            assert_eq!(fixed.matches('\\').count(), src.matches('\\').count());
            assert!(!has_error(&fixed), "{fixed:?}");
        }
    }

    /// The mbedtls `ecdsa.c` shape: a statement-like body with a comment on
    /// its first continued line and a `##` paste further down.
    #[test]
    fn a_statement_macro_with_a_paste_stays_one_directive() {
        let src = "\
#define ENTER(SUB)   do {                     \\
        /* reset ops count */                 \\
        if (ctx != NULL && ctx->SUB == NULL)  \\
        {                                     \\
            ctx->SUB = calloc(1, 8);          \\
            if (ctx->SUB == NULL)             \\
            return -1;                        \\
            restart_## SUB ##_init(ctx->SUB); \\
        }                                     \\
} while (0)

int f(void) { return 0; }
";
        assert!(has_error(src));
        let fixed = blank_define_body_comments(src);
        assert!(!has_error(&fixed), "{fixed:?}");
        assert!(fixed.contains("restart_## SUB ##_init"));
    }

    #[test]
    fn a_define_that_parses_is_left_as_written() {
        for src in [
            "#define A 1 /* c */\nint z;\n",
            "#define A(x) /* c */ do { \\\n  foo(); \\\n} while (0)\nint z;\n",
            "#define A(x) do { \\\n  foo(); \\\n} while (0) /* c */\nint z;\n",
            "#define A(x) do { \\\n  foo(); // c \\\n  bar(); \\\n} while (0)\nint z;\n",
            "#define A(x) do { \\\n  foo(); \\\n} while (0)\nint z;\n",
            "#if A /* c */ \\\n  && B\nint y;\n#endif\n",
            "#define A(x) \"/* not a comment */\" \\\n  x\n",
            "#define Q (64 - P)   /* bits of the hash \\\n    used for the count */\nint z;\n",
        ] {
            assert!(
                matches!(blank_define_body_comments(src), Cow::Borrowed(_)),
                "{src:?}"
            );
        }
    }

    /// A block comment whose line break no `\` splices keeps the directive
    /// going only because it is a comment; blanking it would end the
    /// `#define` there.
    #[test]
    fn a_comment_hiding_a_line_break_is_left_as_written() {
        let src = "#define A 1 /* x\n y */ + \\\n 2\nint z;\n";
        assert!(matches!(blank_define_body_comments(src), Cow::Borrowed(_)));
    }

    /// A line comment spliced onto the next line takes that line with it,
    /// and both are blanked along with the block comment before them; the
    /// `\` stays.
    #[test]
    fn a_spliced_line_comment_is_blanked_with_its_continued_line() {
        let src =
            "#define A(x) do { /* c */ \\\n  foo(x); // d \\\n  more \\\n} while (0)\nint z;\n";
        let fixed = blank_define_body_comments(src);
        assert!(!fixed.contains("more"), "{fixed:?}");
        assert!(!fixed.contains("//"), "{fixed:?}");
        assert!(fixed.contains("foo(x);"), "{fixed:?}");
        assert_eq!(fixed.len(), src.len());
        assert_eq!(fixed.matches('\\').count(), src.matches('\\').count());
    }

    #[test]
    fn non_ascii_in_a_comment_keeps_the_length() {
        let src = "#define A(x) do { /* größe */ \\\n  foo(); \\\n} while (0)\n";
        let fixed = blank_define_body_comments(src);
        assert_eq!(fixed.len(), src.len());
        assert!(!fixed.contains("gr"), "{fixed:?}");
    }

    #[test]
    fn crlf_lines_are_kept() {
        let src = "#define A(x) do { /* c */ \\\r\n  foo(); \\\r\n} while (0)\r\nint z;\r\n";
        let fixed = blank_define_body_comments(src);
        assert_eq!(fixed.matches("\r\n").count(), src.matches("\r\n").count());
        assert!(!fixed.contains("/*"), "{fixed:?}");
    }
}
