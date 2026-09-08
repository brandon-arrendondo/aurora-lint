//! Pre-parse pass: repair a MULTI-ARM `#if`/`#elif`/`#else` chain whose arms
//! each end with an incomplete statement fragment sharing one brace block
//! placed after the `#endif` (task 1070).
//!
//! Same root cause as the single-arm passes this one is the sibling of
//! (`control_header_preproc_guard` for a trailing `if`/`while`/`for` header,
//! `preproc_dangling_else` for a trailing `else`): `preproc_if` is a block
//! item in tree-sitter-c, so the brace block after `#endif` parses as a
//! SIBLING of the header rather than its body, and GLR recovery synthesizes
//! an empty consequence that EXP19-C reads as an unbraced body.
//!
//! Real shape (raylib `platforms/rcore_desktop_sdl.c`, 16 instances):
//! ```c
//! #if defined(USING_VERSION_SDL3)
//!     if (SDL_GetDisplayProperties(monitor) != 0)
//! #else
//!     if ((monitor >= 0) && (monitor < monitorCount))
//! #endif
//!     {
//!         ...
//!     }
//! ```
//!
//! # Why the single-arm repair cannot just drop its `!has_branch` guard
//!
//! Both single-arm passes blank the wrapping directive lines so the fragment
//! rejoins the code it governs. Doing that to a chain splices every arm into
//! ONE statement stream -- `if (a) if (b) { ... }` -- which is worse than the
//! original defect: the outer `if` then has a non-compound consequence and
//! EXP19-C fires where it previously fired once. The repair here therefore
//! keeps ONE arm and removes the others' fragments, accepting the loss of the
//! discarded arms from analysis.
//!
//! # Which arm is kept
//!
//! The LAST arm that ends incomplete, because that is the arm the brace block
//! textually follows once the directives are blank. Keeping it means every
//! earlier arm needs only its trailing FRAGMENT blanked -- the header line, or
//! the bare `else` -- and the rest of that arm's code stays visible. On curl's
//! three-way `hostip4.c` chain that preserves both other arms' bodies
//! (a `gethostbyname_r` call and a complete `if`/`else`) and blanks two
//! tokens. Keeping the first arm instead would require blanking every later
//! arm whole.
//!
//! Any arm AFTER the kept one is blanked entirely, incomplete or not: it sits
//! between the kept header and the brace block, so leaving it would make the
//! header govern its first statement instead. sqlite's `analyze.c` `statGet`
//! is that case -- a `#else` arm holding a complete `assert( argc==1 );`.
//!
//! # What the repair costs
//!
//! Two things, both bounded by how few of these chains exist.
//!
//! The blanked arms leave analysis. Across the nine checkouts that is 21
//! lines over 20 in-scope chains, and every one of them is a dangling
//! fragment whose kept-arm counterpart says the same thing -- raylib's
//! `if (SDL_GetDisplayProperties(monitor) != 0)` against the SDL2 spelling of
//! the same test -- plus one `assert( argc==1 );` in sqlite. No declaration
//! and no call with an effect outside its own condition is discarded.
//!
//! The chain also stops existing in the tree, so `preproc_arms` no longer
//! reports the arms' offsets as mutually exclusive. That fact has nothing
//! left to protect here: the code it would have separated the kept arm from
//! is the code this pass blanked.
//!
//! # What is deliberately NOT matched
//!
//! **A chain not followed by a lone `{`.** The shared brace block is what
//! makes the arms' fragments one construct; without it the chain is some other
//! shape (an `#ifdef` picking between two complete statements, a guard around
//! a declaration) that this repair would only damage. Across the nine
//! real-world checkouts 36 multi-arm chains have an incomplete arm and 24 are
//! followed by `{`; the other 12 are left alone.
//!
//! **A chain whose arms all end complete.** Nothing is split, so there is
//! nothing to repair.

use crate::analyze::control_header_preproc_guard::{
    blank_line, ends_with_control_header, is_branch_directive, is_directive, is_directive_start,
    is_endif, strip_comments,
};
use crate::analyze::preproc_dangling_else::is_bare_else_line;

/// How an arm's last real content line leaves the arm.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ArmEnd {
    /// `if (...)`, `while (...)` or `for (...)` -- needs the statement that
    /// follows the `#endif`.
    ControlHeader,
    /// A bare `else` -- likewise.
    BareElse,
    /// Self-contained, or empty.
    Complete,
}

/// The body lines of one arm: non-blank, non-directive, in source order.
fn arm_body(lines: &[&str], lo: usize, hi: usize) -> Vec<usize> {
    (lo..hi)
        .filter(|&k| !lines[k].trim().is_empty() && !is_directive(lines[k]))
        .collect()
}

/// Join `body`'s lines as the parser would see them with the directives gone.
fn joined(lines: &[&str], body: &[usize]) -> String {
    body.iter()
        .map(|&k| lines[k])
        .collect::<Vec<_>>()
        .join("\n")
}

fn classify(lines: &[&str], body: &[usize]) -> ArmEnd {
    let Some(&last) = body.last() else {
        return ArmEnd::Complete;
    };
    if ends_with_control_header(&joined(lines, body)) {
        return ArmEnd::ControlHeader;
    }
    if is_bare_else_line(lines[last]) {
        return ArmEnd::BareElse;
    }
    ArmEnd::Complete
}

/// The lines making up the trailing incomplete fragment of `body`.
///
/// For a bare `else` that is the last line alone. For a control header it is
/// the shortest suffix of `body` that still reads as one -- a condition may
/// wrap across lines, and blanking only the last of them would leave a
/// half-open parenthesis.
fn fragment_lines(lines: &[&str], body: &[usize], end: ArmEnd) -> Vec<usize> {
    match end {
        ArmEnd::Complete => Vec::new(),
        ArmEnd::BareElse => body.last().copied().into_iter().collect(),
        ArmEnd::ControlHeader => {
            for start in (0..body.len()).rev() {
                if ends_with_control_header(&joined(lines, &body[start..])) {
                    return body[start..].to_vec();
                }
            }
            // `classify` said this arm ends with a header, so some suffix must
            // match; fall back to the whole body rather than blanking nothing.
            body.to_vec()
        }
    }
}

/// Whether the first non-blank line at or after `from` is a lone `{`.
fn shared_brace_follows(lines: &[&str], from: usize) -> bool {
    lines[from..]
        .iter()
        .find(|l| !l.trim().is_empty())
        .is_some_and(|l| strip_comments(l).trim() == "{")
}

/// Repair multi-arm preprocessor chains that split a control-flow header or
/// `else` from the brace block after the `#endif`, per the module docs above.
/// Length-preserving.
pub fn blank_split_chain_preproc(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut line_starts = Vec::with_capacity(lines.len());
    let mut offset = 0usize;
    for line in &lines {
        line_starts.push(offset);
        offset += line.len() + 1; // '\n' (a CRLF's '\r' is left as-is by blank_line)
    }

    let mut out = source.as_bytes().to_vec();

    let mut i = 0usize;
    while i < lines.len() {
        if !is_directive_start(lines[i]) {
            i += 1;
            continue;
        }

        let mut depth = 1i32;
        let mut end_idx = None;
        let mut branches: Vec<usize> = Vec::new();
        let mut j = i + 1;
        while j < lines.len() {
            if is_directive_start(lines[j]) {
                depth += 1;
            } else if is_endif(lines[j]) {
                depth -= 1;
                if depth == 0 {
                    end_idx = Some(j);
                    break;
                }
            } else if depth == 1 && is_branch_directive(lines[j]) {
                branches.push(j);
            }
            j += 1;
        }

        let Some(end_idx) = end_idx else {
            // No matching #endif (truncated snippet, or unbalanced directives
            // elsewhere in the file) -- move on rather than halt the scan.
            i += 1;
            continue;
        };

        // Single-arm chains belong to `control_header_preproc_guard` and
        // `preproc_dangling_else`; this pass exists for the case they refuse.
        if branches.is_empty() || !shared_brace_follows(&lines, end_idx + 1) {
            i += 1;
            continue;
        }

        let mut edges = Vec::with_capacity(branches.len() + 2);
        edges.push(i);
        edges.extend(branches.iter().copied());
        edges.push(end_idx);

        let bodies: Vec<Vec<usize>> = edges
            .windows(2)
            .map(|e| arm_body(&lines, e[0] + 1, e[1]))
            .collect();
        let ends: Vec<ArmEnd> = bodies.iter().map(|b| classify(&lines, b)).collect();

        let keep = ends.iter().rposition(|&e| e != ArmEnd::Complete);
        let Some(keep) = keep else {
            i += 1;
            continue;
        };

        let mut victims: Vec<usize> = Vec::new();
        for (a, body) in bodies.iter().enumerate() {
            if a < keep {
                victims.extend(fragment_lines(&lines, body, ends[a]));
            } else if a > keep {
                // Anything between the kept header and the brace block would
                // become the header's body instead.
                victims.extend(body.iter().copied());
            }
        }

        for k in victims
            .into_iter()
            .chain(std::iter::once(i))
            .chain(branches.iter().copied())
            .chain(std::iter::once(end_idx))
        {
            blank_line(&mut out, line_starts[k], lines[k].len());
        }

        // Advance by one line, not past `end_idx`: a chain nested inside this
        // one must still get its own independent check.
        i += 1;
    }

    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::c_language;

    fn parses_clean(src: &str) -> bool {
        let fixed = blank_split_chain_preproc(src);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(&fixed, None).unwrap();
        !tree.root_node().has_error()
    }

    fn unchanged(src: &str) -> bool {
        blank_split_chain_preproc(src) == src
    }

    #[test]
    fn fixes_two_arms_sharing_one_brace() {
        // raylib platforms/rcore_desktop_sdl.c, GetMonitorPosition.
        let src = "\
int f(int x);
int g(int monitor, int count)
{
#if defined(USING_VERSION_SDL3)
    if (f(monitor) != 0)
#else
    if ((monitor >= 0) && (monitor < count))
#endif
    {
        return 1;
    }
    return 0;
}
";
        assert!(parses_clean(src));
    }

    #[test]
    fn keeps_the_last_incomplete_arm_and_only_the_others_fragments() {
        let src = "\
int f(int x);
int g(int monitor, int count)
{
#if defined(A)
    f(1);
    if (f(monitor) != 0)
#else
    if ((monitor >= 0) && (monitor < count))
#endif
    {
        return 1;
    }
    return 0;
}
";
        let fixed = blank_split_chain_preproc(src);
        // The first arm's own statement survives; only its dangling header
        // and the directive lines go.
        assert!(fixed.contains("    f(1);"));
        assert!(!fixed.contains("if (f(monitor) != 0)"));
        assert!(fixed.contains("if ((monitor >= 0) && (monitor < count))"));
        assert!(parses_clean(src));
    }

    #[test]
    fn fixes_mixed_else_and_header_arms() {
        // curl lib/hostip4.c, the HAVE_GETHOSTBYNAME_R_5/_6/_3 chain: two arms
        // end with a bare `else`, one with an `if (...)` header.
        let src = "\
int f(int x);
int g(void)
{
  int h = 0, res = 0;
#ifdef HAVE_R_5
  h = f(1);
  if (h) {
    ;
  }
  else
#elif defined(HAVE_R_6)
  h = f(2);
  if (!h)
#elif defined(HAVE_R_3)
  res = f(3);
  if (!res) {
    h = 1;
  }
  else
#endif
  {
    h = 0;
  }
  return h;
}
";
        let fixed = blank_split_chain_preproc(src);
        // Every arm's real work survives; only the dangling fragments go.
        assert!(fixed.contains("h = f(1);"));
        assert!(fixed.contains("h = f(2);"));
        assert!(fixed.contains("res = f(3);"));
        assert!(parses_clean(src));
    }

    #[test]
    fn blanks_a_complete_arm_that_follows_the_kept_one() {
        // sqlite src/analyze.c, statGet: the #else arm holds a complete
        // statement, but it sits between the kept `if (...)` and the brace.
        let src = "\
int f(int x);
void g(int argc)
{
#ifdef SQLITE_ENABLE_STAT4
  int eCall = f(argc);
  if (eCall == 1)
#else
  f(argc);
#endif
  {
    f(0);
  }
}
";
        let fixed = blank_split_chain_preproc(src);
        assert!(fixed.contains("if (eCall == 1)"));
        assert!(!fixed.contains("\n  f(argc);\n"));
        assert!(parses_clean(src));
    }

    #[test]
    fn fixes_a_condition_wrapped_across_lines() {
        let src = "\
int f(int x);
int g(int a)
{
#ifdef A
    if (f(a)
     && f(a + 1))
#else
    if (f(a))
#endif
    {
        return 1;
    }
    return 0;
}
";
        let fixed = blank_split_chain_preproc(src);
        // Both lines of the wrapped condition go, not just the last.
        assert!(!fixed.contains("&& f(a + 1)"));
        assert!(parses_clean(src));
    }

    #[test]
    fn leaves_a_chain_with_no_shared_brace_alone() {
        // Two complete alternatives -- the ordinary #ifdef, not a split.
        let src = "\
int f(int x);
int g(int a)
{
#ifdef A
    return f(a);
#else
    return f(a + 1);
#endif
}
";
        assert!(unchanged(src));
    }

    #[test]
    fn leaves_a_chain_whose_arms_end_complete_alone() {
        // Followed by a brace block, but nothing is split across the guard:
        // the block is a plain compound statement in both arms.
        let src = "\
int f(int x);
int g(int a)
{
#ifdef A
    f(a);
#else
    f(a + 1);
#endif
    {
        return 0;
    }
}
";
        assert!(unchanged(src));
    }

    #[test]
    fn leaves_a_single_arm_chain_to_the_pass_that_owns_it() {
        let src = "\
int f(int x);
int g(int a)
{
#ifdef A
    if (f(a))
#endif
    {
        return 1;
    }
    return 0;
}
";
        assert!(unchanged(src));
    }

    #[test]
    fn handles_a_nested_chain_independently() {
        // raylib nests one of these inside another's brace block.
        let src = "\
int f(int x);
int g(int a)
{
#ifdef A
    if (f(a) != 0)
#else
    if (a >= 0)
#endif
    {
#ifdef A
        if (f(a + 1))
#else
        if (f(a + 2) == 0)
#endif
        {
            return 1;
        }
    }
    return 0;
}
";
        assert!(parses_clean(src));
    }

    #[test]
    fn is_length_preserving() {
        let src = "\
int f(int x);
int g(int a)
{
#ifdef A
    if (f(a))
#else
    if (a)
#endif
    { return 1; }
    return 0;
}
";
        assert_eq!(blank_split_chain_preproc(src).len(), src.len());
    }
}
