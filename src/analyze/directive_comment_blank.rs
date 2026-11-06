//! Pre-parse pass: blank a block comment before a directive's name on its line.
//!
//! A comment is one space by the time directives are read (C11 5.1.1.2,
//! phases 3 and 4), so `/* done */ #endif` is a `#endif`, and so are the second
//! line of `/* done` / `*/ #endif` and `# /* done */ endif`. tree-sitter-c
//! reads them so too. The repair passes and the dead-code ranges read a
//! directive from the first character of its line, so to them the `#if` such a
//! line closes was unclosed and the `#if` such a line opens was none.
//!
//! Blanking the comment gives them all the plain directive, and no pass that
//! blanks a directive's line whole can strand the `/*` of a comment that began
//! on an earlier line. The directive itself is found by
//! [`comments_before_directive_names`], so a `#` after code on the line is left
//! alone, even with a comment that spans lines between them (`int a; /* x` /
//! `*/ #endif` has no directive), as is one inside a literal or a comment.
//!
//! The comment's text is gone from the text the rules read, so one that reads
//! comments no longer sees it: `/* fall through */ #endif` before a `case` is
//! an MSC17-C finding. A suppression comment is read from the file as written.
//! Length- and line-preserving.
//!
//! Known limits:
//! - A `#` a line break parts from its name stays as it is: `#\` / `endif`, and
//!   `# /* a` / `b */ endif`. Blanking a comment cannot bring them onto one
//!   line, so a line-reading pass does not see the directive, and a `#if` it
//!   closes is taken for unclosed.

use crate::analyze::paren_preproc_guard::blank_line;
use crate::utility::cert_c::pp_tokens::comments_before_directive_names;

/// Blank every block comment before a directive's name on its line, per the
/// module docs.
pub fn blank_comments_before_directives(source: &str) -> String {
    if !has_comment_beside_hash(source) {
        return source.to_string();
    }
    let comments = comments_before_directive_names(source);
    if comments.is_empty() {
        return source.to_string();
    }
    let mut out = source.as_bytes().to_vec();
    for range in comments {
        blank_line(&mut out, range.start, range.len());
    }
    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

/// Whether a `*/` and blanks stand before any `#`, or blanks and a `/*` after
/// one: a cheap test that nearly every file fails, so it is not lexed here.
/// Each `#` looks only as far as the blanks on either side of it.
fn has_comment_beside_hash(source: &str) -> bool {
    let is_blank = |c: &u8| matches!(c, b' ' | b'\t' | 0x0b | 0x0c);
    let b = source.as_bytes();
    b.iter().enumerate().any(|(hash, &c)| {
        c == b'#' && {
            let end = b[..hash]
                .iter()
                .rposition(|c| !is_blank(c))
                .map_or(0, |p| p + 1);
            let next = b[hash + 1..]
                .iter()
                .position(|c| !is_blank(c))
                .unwrap_or(b.len());
            b[..end].ends_with(b"*/")
                || b[hash + 1..]
                    .get(next..)
                    .is_some_and(|r| r.starts_with(b"/*"))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::control_header_preproc_guard::blank_control_header_guarded_preproc;
    use crate::analyze::unclosed_conditional_blank::blank_unclosed_conditionals;
    use crate::parser::c_language;

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&c_language()).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn a_comment_before_a_directive_is_blanked() {
        assert_eq!(
            blank_comments_before_directives("#if A\nint a;\n/* */ #endif\n"),
            "#if A\nint a;\n      #endif\n"
        );
        assert_eq!(
            blank_comments_before_directives("  /* a */ /* b */ # else\n"),
            "                  # else\n"
        );
    }

    #[test]
    fn a_comment_between_the_hash_and_the_name_is_blanked() {
        assert_eq!(
            blank_comments_before_directives("# /* old */ endif\n"),
            "#           endif\n"
        );
        assert_eq!(
            blank_comments_before_directives("#/* a */if B\n"),
            "#       if B\n"
        );
    }

    #[test]
    fn a_comment_before_a_vertical_tab_is_blanked() {
        assert_eq!(
            blank_comments_before_directives("/* old */\u{b}#endif\n"),
            "          #endif\n"
        );
    }

    #[test]
    fn a_hash_a_line_break_parts_from_its_name_is_left() {
        for src in ["# /* a\n b */ endif\n", "# /* a */ \\\nendif\n"] {
            assert_eq!(blank_comments_before_directives(src), src, "{src:?}");
        }
    }

    #[test]
    fn a_comment_begun_on_an_earlier_line_goes_with_it() {
        assert_eq!(
            blank_comments_before_directives("/* a\r\n b */ #endif\r\n"),
            "    \r\n      #endif\r\n"
        );
    }

    #[test]
    fn what_is_no_directive_is_left() {
        for src in [
            "int a; /* x */ #endif\n",
            "int a; /* x\n y */ #endif\n",
            "char *s = \"/* x */ #endif\";\n",
            "char *s = \"*/ #endif\";\n",
            "/* x */ int a;\n",
            "/* x */\n#endif\n",
            "// /* x */ #endif\n",
            "/* x */ // #endif\n",
            "/* /* x */ #endif */\n",
        ] {
            let expected = if src.starts_with("/* /*") {
                "           #endif */\n"
            } else {
                src
            };
            assert_eq!(blank_comments_before_directives(src), expected, "{src:?}");
        }
    }

    #[test]
    fn a_conditional_closed_after_a_comment_is_no_unclosed_one() {
        let src = "#if A\nint a;\n/* done */ #endif\nint b;\n";
        let out = blank_unclosed_conditionals(&blank_comments_before_directives(src));
        assert!(out.starts_with("#if A\n"), "{out:?}");
        assert!(!parse(&out).root_node().has_error());
    }

    #[test]
    fn a_guard_closed_after_a_comment_is_paired_by_the_header_pass() {
        let src = "void f(int c){\n#if A\nif (c)\n/* A */ #endif\n{ c++; }\n}\n";
        let out = blank_control_header_guarded_preproc(&blank_comments_before_directives(src));
        assert_eq!(out.lines().nth(1).map(str::trim), Some(""));
        assert_eq!(out.lines().nth(3).map(str::trim), Some(""));
        assert!(!parse(&out).root_node().has_error());
    }

    #[test]
    fn the_utf8_of_a_comment_and_the_length_are_kept_whole() {
        let src = "/* caf\u{e9} */ #endif\n";
        let out = blank_comments_before_directives(src);
        assert_eq!(out.len(), src.len());
        assert!(out.trim_start().starts_with("#endif"));
    }
}
