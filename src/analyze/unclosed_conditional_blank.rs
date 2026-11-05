//! Pre-parse pass: blank a conditional no `#endif` closes.
//!
//! A `#if`, `#ifdef` or `#ifndef` still open at the end of the file (a
//! truncated or generated file, or a header whose `#endif` was lost in a
//! merge) is a `preproc_if` with no end to tree-sitter-c. Recovery then
//! wraps everything from it to the end of the file in `ERROR` nodes, and a
//! file of many such lines parses as one root `ERROR` whose children are
//! every declaration in the file, side by side. Climbing from a node to an
//! ancestor costs time linear in the number of a parent's children there,
//! so every rule that asks for a node's ancestors is quadratic on such a
//! file: a few thousand lines of them held a scan for minutes.
//!
//! No configuration compiles a conditional that is never closed, so there
//! is no arm to choose. The pass blanks the opening directive and its own
//! `#elif`/`#else` lines (not those of a conditional nested in it), and
//! keeps the code of every arm, as the passes that blank a guard keep the
//! code it guarded. A closed conditional inside it is left as it is.
//!
//! An arm a literal condition proves dead (`#if 0`, or the `#else` of
//! `#if 1`) is blanked whole: the dead-code ranges already keep its text out
//! of analysis, and kept as code it would be read once its directive is
//! gone. No block comment crosses the edge of an arm: a directive line
//! inside one is comment text, and a comment a directive opens is part of
//! the directive, so blanking a dead arm strands no end of a comment.
//!
//! A directive is read as [`directive_extent`] reads it, with its
//! `\`-continuations and the rest of a block comment it opens, so nothing
//! of it is left behind as code. A `#if` line that starts inside a block
//! comment is comment text and opens nothing. Length- and line-preserving.

use crate::analyze::init_state::literal_dead_lines;
use crate::analyze::paren_preproc_guard::{blank_line, CodeLines};
use crate::analyze::preproc_arm_choice::directive_extent;
use crate::analyze::preproc_conditionals::{cond_line, match_conditionals};

/// Blank every conditional no `#endif` closes, per the module docs.
pub fn blank_unclosed_conditionals(source: &str) -> String {
    let code = CodeLines::new(source);
    let conditionals = match_conditionals(code.len(), |k| {
        (!code.starts_in_comment[k])
            .then(|| cond_line(code.raw[k]))
            .flatten()
    });
    if conditionals.unclosed().is_empty() {
        return source.to_string();
    }
    // Arms of nested unclosed conditionals each run to the end of the
    // file, so an arm is tested against a running count of live lines, and
    // the lines to blank are marked as ranges and blanked once.
    let live_before = live_line_counts(&dead_lines(source, code.len()));
    let mut marked = vec![0i32; code.len() + 1];
    let mut mark = |r: std::ops::Range<usize>| {
        marked[r.start] = marked[r.start].saturating_add(1);
        marked[r.end] = marked[r.end].saturating_sub(1);
    };
    for (open, branches) in conditionals.unclosed() {
        let directives: Vec<usize> = std::iter::once(*open)
            .chain(branches.iter().copied())
            .collect();
        for (n, &d) in directives.iter().enumerate() {
            let extent = directive_extent(&code.raw, d);
            let end = directives.get(n + 1).copied().unwrap_or(code.len());
            let arm = extent.end.min(end)..end;
            mark(extent);
            if !arm.is_empty() && live_before[arm.end] == live_before[arm.start] {
                mark(arm);
            }
        }
    }
    let mut out = source.as_bytes().to_vec();
    let mut depth = 0i32;
    for (k, d) in marked[..code.len()].iter().enumerate() {
        depth = depth.saturating_add(*d);
        if depth > 0 {
            blank_line(&mut out, code.starts[k], code.raw[k].len());
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

/// `counts[k]`: how many of the lines before line `k` are not dead.
fn live_line_counts(dead: &[bool]) -> Vec<usize> {
    let mut counts = Vec::with_capacity(dead.len() + 1);
    counts.push(0);
    for &d in dead {
        counts.push(counts[counts.len() - 1] + usize::from(!d));
    }
    counts
}

/// By line: whether a literal condition proves it dead, per
/// [`literal_dead_lines`], whose ranges are 1-based and inclusive.
fn dead_lines(source: &str, len: usize) -> Vec<bool> {
    let mut opened = vec![0i32; len + 1];
    for (s, e) in literal_dead_lines(source) {
        let (s, e) = (s.saturating_sub(1).min(len), e.min(len));
        if s < e {
            opened[s] = opened[s].saturating_add(1);
            opened[e] = opened[e].saturating_sub(1);
        }
    }
    let mut depth = 0i32;
    opened[..len]
        .iter()
        .map(|d| {
            depth = depth.saturating_add(*d);
            depth > 0
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::c_language;

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&c_language()).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn an_unclosed_if_and_its_else_are_blanked_and_their_code_kept() {
        let src = "#if A\nint a;\n#else\nint b;\n";
        let out = blank_unclosed_conditionals(src);
        assert_eq!(out, "     \nint a;\n     \nint b;\n");
        assert!(!parse(&out).root_node().has_error());
    }

    #[test]
    fn a_closed_conditional_is_left_and_one_inside_an_unclosed_one_too() {
        let closed = "#ifdef A\nint a;\n#else\nint b;\n#endif\n";
        assert_eq!(blank_unclosed_conditionals(closed), closed);
        let src = "#ifndef A\n#if B\nint b;\n#else\nint c;\n#endif\n#elif C\nint d;\n";
        assert_eq!(
            blank_unclosed_conditionals(src),
            "         \n#if B\nint b;\n#else\nint c;\n#endif\n       \nint d;\n"
        );
    }

    #[test]
    fn of_two_ifs_and_one_endif_the_outer_is_blanked() {
        let src = "#if A\n#if B\nint b;\n#endif\nint a;\n";
        assert_eq!(
            blank_unclosed_conditionals(src),
            "     \n#if B\nint b;\n#endif\nint a;\n"
        );
    }

    #[test]
    fn a_continued_directive_and_the_comment_it_opens_go_with_it() {
        let src = "#if defined(A) || \\\n    defined(B) /* why\n   */\nint a;\n";
        let out = blank_unclosed_conditionals(src);
        assert_eq!(out.len(), src.len());
        assert_eq!(out.lines().filter(|l| l.trim().is_empty()).count(), 3);
        assert!(!parse(&out).root_node().has_error());
    }

    #[test]
    fn an_if_in_a_block_comment_opens_nothing() {
        let src = "/*\n#if A\n*/\nint a;\n";
        assert_eq!(blank_unclosed_conditionals(src), src);
    }

    #[test]
    fn a_dead_arm_is_blanked_whole_and_a_live_one_kept() {
        let src = "#if 0\nint a;\n#else\nint b;\n";
        assert_eq!(
            blank_unclosed_conditionals(src),
            "     \n      \n     \nint b;\n"
        );
        let src = "#if 1\nint a;\n#else\nint b;\n";
        assert_eq!(
            blank_unclosed_conditionals(src),
            "     \nint a;\n     \n      \n"
        );
        let src = "#if 0\nint a;\nint b;\n";
        assert_eq!(blank_unclosed_conditionals(src).trim(), "");
    }

    #[test]
    fn a_closed_if_0_in_a_live_arm_is_left() {
        let src = "#ifdef A\nint a;\n#if 0\nint b;\n#endif\n";
        assert_eq!(
            blank_unclosed_conditionals(src),
            "        \nint a;\n#if 0\nint b;\n#endif\n"
        );
    }

    #[test]
    fn an_else_in_a_comment_of_a_dead_arm_is_dead_text_too() {
        let src = "#if 0\nint a; /* open\n#else\nclose */ int b;\n";
        let out = blank_unclosed_conditionals(src);
        assert_eq!(out.len(), src.len());
        assert_eq!(out.trim(), "");
    }

    #[test]
    fn a_file_of_unclosed_ifs_parses_without_error() {
        let src: String = (0..200).map(|i| format!("#if A{i}\nint a{i};\n")).collect();
        assert!(parse(&src).root_node().has_error());
        assert!(!parse(&blank_unclosed_conditionals(&src))
            .root_node()
            .has_error());
    }
}
