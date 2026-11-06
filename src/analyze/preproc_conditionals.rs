//! The conditionals of a file, matched once, for the pre-parse repair
//! passes.
//!
//! Each pass used to find a conditional's `#elif`/`#else` lines and its
//! `#endif` by scanning forward from every `#if`, to the end of the file
//! when none closes it. A file of many unclosed `#if` lines (a truncated or
//! generated file) then cost time quadratic in its length, once per pass.
//! [`match_conditionals`] matches every conditional in one stack pass, with
//! the same answer the forward scan gave for each `#if`.
//!
//! It also holds the passes' one reading of a conditional directive,
//! [`directive_keyword`] and the predicates on it. Two passes used to match
//! a `#if` or `#endif` prefix, and so missed `# else` and `#  endif`, which
//! are the same directives.
//!
//! [`directive_lines`] says which lines hold a directive at all, as a compiler
//! does.

use crate::utility::cert_c::pp_tokens::directive_starts;

/// By line, `line_starts` being where each line of `source` starts: whether
/// it holds a directive, read as a compiler reads one
/// ([`directive_starts`]). A `#` line inside a block comment, a `\`-continued
/// string or a `\`-continued `//` comment holds none, nor does one a `\`
/// joins to code before it.
pub(crate) fn directive_lines(source: &str, line_starts: &[usize]) -> Vec<bool> {
    let mut directive = vec![false; line_starts.len()];
    for hash in directive_starts(source) {
        directive[line_starts.partition_point(|&s| s <= hash) - 1] = true;
    }
    directive
}

/// The keyword of the directive `line` is, if it is one: `"ifndef"` for
/// `#ifndef X`, `# ifndef X` and `#  ifndef X` alike. White space may stand
/// between the `#` and the directive's name (C11 6.10p2), and nested
/// conditionals are often indented that way (pure-ftpd's `# ifndef`), so a
/// line is never matched on a `#if` or `#endif` prefix.
pub(crate) fn directive_keyword(line: &str) -> Option<&str> {
    directive_parts(line).map(|(keyword, _)| keyword)
}

/// The keyword of the directive `line` is, as [`directive_keyword`] reads
/// it, and the text after it. The keyword runs as far as an identifier
/// would: an identifier may hold characters outside ASCII (C11 6.4.2.1), so
/// `#ifé X` names the directive `ifé`, which is no `#if`.
pub(crate) fn directive_parts(line: &str) -> Option<(&str, &str)> {
    let rest = line.trim_start().strip_prefix('#')?.trim_start();
    let end = rest
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    Some(rest.split_at(end))
}

/// `#if`, `#ifdef` or `#ifndef`.
pub(crate) fn is_directive_start(line: &str) -> bool {
    matches!(directive_keyword(line), Some("if" | "ifdef" | "ifndef"))
}

/// `#endif`.
pub(crate) fn is_endif(line: &str) -> bool {
    directive_keyword(line) == Some("endif")
}

/// `#elif`, C23's `#elifdef` and `#elifndef`, or `#else`.
pub(crate) fn is_branch_directive(line: &str) -> bool {
    matches!(
        directive_keyword(line),
        Some("else" | "elif" | "elifdef" | "elifndef")
    )
}

/// What `line` is to the conditional structure, by [`directive_keyword`].
pub(crate) fn cond_line(line: &str) -> Option<CondLine> {
    if is_directive_start(line) {
        Some(CondLine::Open)
    } else if is_endif(line) {
        Some(CondLine::End)
    } else if is_branch_directive(line) {
        Some(CondLine::Branch)
    } else {
        None
    }
}

/// What a line is to the conditional structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CondLine {
    /// `#if`, `#ifdef` or `#ifndef`.
    Open,
    /// `#elif` (and its C23 forms) or `#else`.
    Branch,
    /// `#endif`.
    End,
}

/// One conditional: its own `#elif`/`#else` lines (not a nested
/// conditional's), in order, and its `#endif`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Conditional {
    pub(crate) branches: Vec<usize>,
    pub(crate) endif: usize,
}

/// Every conditional of a file of `len` lines, matched in one pass.
/// `kind(k)` says what line `k` is; a line it answers `None` for is not a
/// directive the matching counts.
pub(crate) struct Conditionals {
    /// By the line of the `#if`: its conditional, or `None` when no line
    /// closes it, or the line opens none.
    by_open: Vec<Option<Conditional>>,
    /// By the line of the `#endif`: the `#if` it closes, or `None` when it
    /// closes none, or the line is no `#endif`.
    by_end: Vec<Option<usize>>,
    /// Every `#if` no line closes, in line order, with its own
    /// `#elif`/`#else` lines.
    unclosed: Vec<(usize, Vec<usize>)>,
}

impl Conditionals {
    /// The conditional the `#if` on line `open` begins, if it is closed.
    pub(crate) fn at(&self, open: usize) -> Option<&Conditional> {
        self.by_open.get(open)?.as_ref()
    }

    /// The `#if` line the `#endif` on line `end` closes, if any.
    pub(crate) fn opener_of(&self, end: usize) -> Option<usize> {
        *self.by_end.get(end)?
    }

    /// Every `#if` still open at the end of the file, in line order, each
    /// with its own `#elif`/`#else` lines (not those of a conditional
    /// nested in it).
    pub(crate) fn unclosed(&self) -> &[(usize, Vec<usize>)] {
        &self.unclosed
    }
}

/// Match the conditionals of `len` lines classified by `kind`. A stray
/// `#endif` or `#elif` (one no `#if` is open for) is ignored, and an `#if`
/// still open at the end of the file has no conditional, as the forward
/// scan from it would have found; [`Conditionals::unclosed`] lists those.
pub(crate) fn match_conditionals(
    len: usize,
    kind: impl Fn(usize) -> Option<CondLine>,
) -> Conditionals {
    let mut by_open = vec![None; len];
    let mut by_end = vec![None; len];
    let mut open: Vec<(usize, Vec<usize>)> = Vec::new();
    for (k, closes) in by_end.iter_mut().enumerate() {
        match kind(k) {
            Some(CondLine::Open) => open.push((k, Vec::new())),
            Some(CondLine::Branch) => {
                if let Some((_, branches)) = open.last_mut() {
                    branches.push(k);
                }
            }
            Some(CondLine::End) => {
                if let Some((start, branches)) = open.pop() {
                    by_open[start] = Some(Conditional { branches, endif: k });
                    *closes = Some(start);
                }
            }
            None => {}
        }
    }
    Conditionals {
        by_open,
        by_end,
        unclosed: open,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(lines: &[&str]) -> Conditionals {
        match_conditionals(lines.len(), |k| match lines[k] {
            "if" => Some(CondLine::Open),
            "else" => Some(CondLine::Branch),
            "endif" => Some(CondLine::End),
            _ => None,
        })
    }

    /// The forward scan each pass used to run from line `i`.
    fn forward(lines: &[&str], i: usize) -> Option<Conditional> {
        if lines[i] != "if" {
            return None;
        }
        let mut depth = 1;
        let mut branches = Vec::new();
        for (j, l) in lines.iter().enumerate().skip(i + 1) {
            match *l {
                "if" => depth += 1,
                "endif" => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(Conditional { branches, endif: j });
                    }
                }
                "else" if depth == 1 => branches.push(j),
                _ => {}
            }
        }
        None
    }

    /// The `#else` lines at the depth of the `#if` on line `i`, to the end
    /// of the file: an unclosed conditional's own branches.
    fn own_branches(lines: &[&str], i: usize) -> Vec<usize> {
        let mut depth = 1;
        let mut branches = Vec::new();
        for (j, l) in lines.iter().enumerate().skip(i + 1) {
            match *l {
                "if" => depth += 1,
                "endif" => depth -= 1,
                "else" if depth == 1 => branches.push(j),
                _ => {}
            }
        }
        branches
    }

    /// The backward scan from an `#endif` on line `e` to its `#if`.
    fn backward(lines: &[&str], e: usize) -> Option<usize> {
        if lines[e] != "endif" {
            return None;
        }
        let mut depth = 1;
        for j in (0..e).rev() {
            match lines[j] {
                "endif" => depth += 1,
                "if" => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(j);
                    }
                }
                _ => {}
            }
        }
        None
    }

    #[test]
    fn every_if_gets_the_conditional_a_forward_scan_finds() {
        // Every sequence of up to seven of these lines: nesting, branches,
        // stray and missing #endif lines alike.
        let alphabet = ["if", "else", "endif", "x"];
        for n in 0..=7u32 {
            for code in 0..4usize.pow(n) {
                let lines: Vec<&str> = (0..n).map(|p| alphabet[code / 4usize.pow(p) % 4]).collect();
                let c = classify(&lines);
                let unclosed: Vec<(usize, Vec<usize>)> = (0..lines.len())
                    .filter(|&i| lines[i] == "if" && forward(&lines, i).is_none())
                    .map(|i| (i, own_branches(&lines, i)))
                    .collect();
                assert_eq!(c.unclosed(), unclosed.as_slice(), "{lines:?}");
                for i in 0..lines.len() {
                    assert_eq!(c.opener_of(i), backward(&lines, i), "{lines:?} at {i}");
                    let expected = forward(&lines, i);
                    assert_eq!(c.at(i), expected.as_ref(), "{lines:?} at {i}");
                    if let Some(cond) = expected {
                        assert_eq!(c.opener_of(cond.endif), Some(i), "{lines:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn a_keyword_is_read_however_the_directive_is_spaced() {
        for line in ["#endif", "# endif", "  #\tendif /* x */", "#endif//x"] {
            assert_eq!(directive_keyword(line), Some("endif"), "{line:?}");
            assert_eq!(cond_line(line), Some(CondLine::End), "{line:?}");
        }
        for line in ["# else", "#elif X", "#  elifdef X", "#elifndef X"] {
            assert_eq!(cond_line(line), Some(CondLine::Branch), "{line:?}");
        }
        for line in ["# if X", "#ifdef X", "#  ifndef X"] {
            assert_eq!(cond_line(line), Some(CondLine::Open), "{line:?}");
        }
        // A longer name is another directive (or none), not a prefix match.
        for line in [
            "#ifdefX",
            "#if_x",
            "#endiff",
            "#elsewhere",
            "#if\u{e9} X",
            "#endif\u{3b1}",
            "#include <a.h>",
            "x # if",
        ] {
            assert_eq!(cond_line(line), None, "{line:?}");
        }
    }

    #[test]
    fn a_stray_endif_closes_nothing() {
        let c = classify(&["endif", "if", "endif"]);
        assert_eq!(c.opener_of(0), None);
        assert_eq!(c.opener_of(2), Some(1));
    }
}
