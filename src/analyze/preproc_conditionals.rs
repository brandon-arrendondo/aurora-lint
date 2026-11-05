//! The conditionals of a file, matched once, for the pre-parse repair
//! passes.
//!
//! Each pass used to find a conditional's `#elif`/`#else` lines and its
//! `#endif` by scanning forward from every `#if`, to the end of the file
//! when none closes it. A file of many unclosed `#if` lines (a truncated or
//! generated file) then cost time quadratic in its length, once per pass.
//! [`match_conditionals`] matches every conditional in one stack pass, with
//! the same answer the forward scan gave for each `#if`.

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
}

/// Match the conditionals of `len` lines classified by `kind`. A stray
/// `#endif` or `#elif` (one no `#if` is open for) is ignored, and an `#if`
/// still open at the end of the file has no conditional, as the forward
/// scan from it would have found.
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
    Conditionals { by_open, by_end }
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
    fn a_stray_endif_closes_nothing() {
        let c = classify(&["endif", "if", "endif"]);
        assert_eq!(c.opener_of(0), None);
        assert_eq!(c.opener_of(2), Some(1));
    }
}
