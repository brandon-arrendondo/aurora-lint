//! Pre-parse pass: join an `else` to a conditional that supplies its body
//! as one braced block per arm.
//!
//! Real shape (mbedtls `ssl_tls.c`, `ssl_set_handshake_prfs` and its twin):
//! ```c
//! #if defined(A)
//!     if (hash == SHA384) {
//!         ...
//!     } else
//! #endif
//! #if defined(B)
//!     {
//!         ... the SHA-256 setup ...
//!     }
//! #else
//!     {
//!         return ERROR;
//!     }
//! #endif
//! ```
//!
//! `preproc_if` is a block item in tree-sitter-c, and the grammar has no
//! production for an `else` followed by one: the `else` becomes an `ERROR`,
//! and the arms after it read as statements following the `if`, every arm in
//! sequence. `preproc_dangling_else` cannot join the outer guard either,
//! because what follows its `#endif` is a directive rather than code. In a
//! long function that is one more error for recovery to absorb, and mbedtls's
//! `ssl_tls.c` parses as one root `ERROR` node.
//!
//! The repair keeps ONE arm: the first, which is the block the `else` reaches
//! once the directives are blank. Every later arm is blanked whole, so it
//! cannot read as a statement after the `if`: kept, it would run after the
//! else body on every path, which no configuration compiles (ADR-0010
//! Decision 4). Keeping the first arm needs no condition decided, so the
//! repair never depends on the profile, and the code it keeps is the one the
//! guard was written to add: in the shape above, the SHA-256 setup rather
//! than the error stub `preproc_arm_choice::compiled_arm` would pick with `B`
//! read as undefined. The dropped arms leave analysis -- the same cost
//! `preproc_split_chain` accepts for the arms it blanks.
//!
//! A single-arm `#if B` / `{ ... }` / `#endif` (the same file's
//! `ssl_tls12prf_from_cs`) loses nothing: its directives are blanked and the
//! block becomes the else body, which is the program with `B` defined. With
//! `B` off the `else` would take whatever statement follows instead; joining
//! reads one configuration, as `preproc_dangling_else` does for the guard
//! around the `if`.
//!
//! Deliberately narrow: every arm (`#elif` included) is exactly one balanced
//! `{ ... }` block with no directive of its own inside, the first arm's
//! condition is not a literal `0`, and the code line before the `#if`, or
//! before the `#endif` directly ahead of it, ends with the keyword `else`.
//! Length- and line-preserving: only whole lines are blanked.

use crate::analyze::paren_preproc_guard::{
    blank_line, is_branch_directive, is_directive, is_directive_start, is_endif, CodeLines,
};
use crate::analyze::preproc_arm_choice::directive_extent;

/// True if code line `k` ends with the keyword `else`.
fn ends_with_else(code: &str) -> bool {
    code.trim_end()
        .strip_suffix("else")
        .is_some_and(|before| !before.ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_'))
}

/// The nearest line before `i` holding code or a directive, skipping blank
/// and comment-only lines.
fn previous_line(code: &CodeLines, i: usize) -> Option<usize> {
    (0..i)
        .rev()
        .find(|&k| !code.code[k].trim().is_empty() || is_directive(code.raw[k]))
}

/// True if the conditional opening at line `i` follows an `else`: directly,
/// or across the `#endif` of the guard that holds that `else`.
fn follows_else(code: &CodeLines, i: usize) -> bool {
    let Some(k) = previous_line(code, i) else {
        return false;
    };
    let k = if is_endif(code.raw[k]) && !code.starts_in_comment[k] {
        match previous_line(code, k) {
            Some(k) => k,
            None => return false,
        }
    } else {
        k
    };
    !is_directive(code.raw[k]) && ends_with_else(&code.code[k])
}

/// True if the code lines `arm` are exactly one balanced brace block: the
/// first code is `{`, the last is the `}` that closes it, and nothing
/// outside it.
fn is_one_braced_block(code: &CodeLines, arm: std::ops::Range<usize>) -> bool {
    let text: String = arm
        .map(|k| code.code[k].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let text = text.trim();
    if !text.starts_with('{') || !text.ends_with('}') {
        return false;
    }
    let (mut braces, mut parens) = (0i32, 0i32);
    let last = text.len() - 1;
    for (pos, c) in text.char_indices() {
        match c {
            '{' => braces += 1,
            '}' => braces -= 1,
            '(' => parens += 1,
            ')' => parens -= 1,
            _ => continue,
        }
        if braces < 0 || parens < 0 || (braces == 0 && pos != last) {
            return false;
        }
    }
    braces == 0 && parens == 0
}

/// The conditional opening at line `i`: the line of each arm's directive
/// (`#if`, then each `#elif`/`#else`) and of its `#endif`. `None` if it does
/// not close, or holds a directive conditional of its own.
fn arms(code: &CodeLines, i: usize) -> Option<(Vec<usize>, usize)> {
    let mut openers = vec![i];
    let mut j = directive_extent(&code.raw, i).end;
    while j < code.len() {
        let line = code.raw[j];
        if !code.starts_in_comment[j] {
            if is_directive_start(line) {
                return None;
            }
            if is_branch_directive(line) {
                openers.push(j);
            } else if is_endif(line) {
                return Some((openers, j));
            }
        }
        j += 1;
    }
    None
}

/// True if the `#if` on `line` tests a literal `0`: an arm no configuration
/// compiles, which this pass must not keep.
fn is_if_zero(line: &str) -> bool {
    let rest = line.trim_start().trim_start_matches('#').trim_start();
    rest.strip_prefix("if")
        .is_some_and(|cond| cond.split("//").next().unwrap_or("").trim() == "0")
}

/// Join each `else` to a conditional of braced arms after it, per the module
/// docs. Length- and line-preserving.
pub fn join_else_to_braced_arms(source: &str) -> String {
    let code = CodeLines::new(source);
    let mut out = source.as_bytes().to_vec();
    let mut changed = false;
    let mut i = 0usize;
    while i < code.len() {
        if code.starts_in_comment[i] || !is_directive_start(code.raw[i]) {
            i += 1;
            continue;
        }
        let Some((openers, endif)) = arms(&code, i) else {
            i += 1;
            continue;
        };
        let bounds: Vec<std::ops::Range<usize>> = openers
            .iter()
            .enumerate()
            .map(|(n, &o)| {
                let end = openers.get(n + 1).copied().unwrap_or(endif);
                directive_extent(&code.raw, o).end..end
            })
            .collect();
        let qualifies = !is_if_zero(code.raw[i])
            && bounds
                .iter()
                .all(|arm| is_one_braced_block(&code, arm.clone()))
            && follows_else(&code, i);
        if !qualifies {
            i += 1;
            continue;
        }
        for &d in openers.iter().chain(std::iter::once(&endif)) {
            for k in directive_extent(&code.raw, d) {
                blank_line(&mut out, code.starts[k], code.raw[k].len());
            }
        }
        for arm in &bounds[1..] {
            for k in arm.clone() {
                blank_line(&mut out, code.starts[k], code.raw[k].len());
            }
        }
        changed = true;
        i = endif + 1;
    }
    if !changed {
        return source.to_string();
    }
    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::CParser;

    fn parses_clean(src: &str) -> bool {
        let (tree, _) = CParser::new().unwrap().parse_source(src).unwrap();
        !tree.root_node().has_error()
    }

    const GUARDED: &str = "\
int g(int v);
int f(int h)
{
#if defined(A)
    if (h == 1) {
        g(1);
    } else
#endif
#if defined(B)
    {
        g(2);
    }
#else
    {
        return -1;
    }
#endif
    return 0;
}
";

    #[test]
    fn keeps_the_first_arm_as_the_else_body() {
        let out = join_else_to_braced_arms(GUARDED);
        assert_eq!(out.len(), GUARDED.len());
        assert_eq!(out.lines().count(), GUARDED.lines().count());
        assert!(out.contains("g(2);"));
        assert!(!out.contains("return -1;"));
        assert!(!out.contains("#if defined(B)"));
        assert!(!out.contains("#else"));
        // The outer guard is the dangling-else pass's, run after this one.
        assert!(out.contains("#if defined(A)"));
        assert!(parses_clean(GUARDED));
    }

    #[test]
    fn joins_an_unguarded_else_and_an_elif_chain() {
        let src = "\
int g(int v);
int f(int h)
{
    if (h == 1) {
        g(1);
    } else /* the rest by build */
#if defined(B)
    {
        g(2);
    }
#elif defined(C)
    { g(3); }
#else
    {
        g(4);
    }
#endif
    return 0;
}
";
        let out = join_else_to_braced_arms(src);
        assert!(out.contains("g(2);"));
        assert!(!out.contains("g(3);"));
        assert!(!out.contains("g(4);"));
        assert!(parses_clean(src));
    }

    #[test]
    fn a_single_arm_block_becomes_the_else_body_whole() {
        let src = "\
int g(int v);
int f(int h)
{
    if (h == 1) {
        g(1);
    } else
#if defined(B)
    {
        g(2);
    }
#endif
    return 0;
}
";
        let out = join_else_to_braced_arms(src);
        assert!(!out.contains('#'));
        assert!(out.contains("g(2);"));
        assert!(parses_clean(src));
    }

    #[test]
    fn leaves_conditionals_that_are_not_a_choice_of_else_bodies() {
        let no_else = GUARDED.replace("    } else\n#endif", "    }\n#endif");
        assert_eq!(join_else_to_braced_arms(&no_else), no_else);

        let two_statements = GUARDED.replace(
            "        return -1;\n    }\n",
            "        g(3);\n    }\n    g(4);\n",
        );
        assert_eq!(join_else_to_braced_arms(&two_statements), two_statements);

        let nested = GUARDED.replace("        g(2);\n", "#if defined(C)\n        g(2);\n#endif\n");
        assert_eq!(join_else_to_braced_arms(&nested), nested);

        let if_zero = GUARDED.replace("#if defined(B)", "#if 0");
        assert_eq!(join_else_to_braced_arms(&if_zero), if_zero);

        let identifier = GUARDED.replace("    } else\n#endif", "    } elsewhere\n#endif");
        assert_eq!(join_else_to_braced_arms(&identifier), identifier);
    }
}
