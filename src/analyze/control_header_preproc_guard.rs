//! Pre-parse pass: blank a `#if`/`#ifdef`/`#ifndef` + matching `#endif` pair
//! whose guarded block ends with a control-flow HEADER -- `if (...)`,
//! `while (...)` or `for (...)` -- leaving the statement that header governs
//! on the far side of the `#endif`.
//!
//! Real shape (sqlite `wherecode.c`, `sqlite3WhereExplainOneScan`):
//! ```c
//! int ret = 0;
//! #if !defined(SQLITE_DEBUG)
//!   if( sqlite3ParseToplevel(pParse)->explain==2 || IS_STMT_SCANSTATUS(pParse->db) )
//! #endif
//!   {
//!     ...
//!   }
//! ```
//!
//! In every configuration that actually compiles this is well-formed: with
//! `SQLITE_DEBUG` undefined the `if` governs the brace block, and with it
//! defined the block is a plain compound statement. Only the unpreprocessed
//! text is broken, and only because the guard falls between the header and
//! its body.
//!
//! `tree-sitter-c` has no production for that. `preproc_if` is a block item,
//! so the `if` is parsed *inside* it and the brace block becomes a following
//! SIBLING, which leaves the `if` needing a consequence it cannot reach.
//! GLR recovery synthesizes an empty one:
//!
//! ```text
//! (preproc_if
//!   (if_statement
//!     condition: (parenthesized_expression ...)
//!     consequence: (expression_statement (MISSING ";"))))
//! (compound_statement ...)          <- the real body, now a sibling
//! ```
//!
//! `has_error` is true on the resulting tree. EXP19-C reads that synthesized
//! empty statement as an unbraced body and reports "if statement body should
//! be enclosed in braces" against an `if` that is braced in every build.
//!
//! Fix, mirroring `preproc_dangling_else`, `label_preproc_guard` and
//! `paren_preproc_guard`: blank the opening directive line and its matching
//! `#endif` (same-length whitespace, newlines preserved), so the header
//! rejoins the body it governs. The cost is the one those passes accept --
//! aurora-lint's "maybe compiled" `#ifdef` branch modeling
//! (`process_preproc_conditional` in `analyze::cfg`) is lost for this
//! fragment, so the guarded arm is read as unconditionally present. Here
//! that is the arm in which the header exists at all, which is the only arm
//! in which there is anything to analyze.
//!
//! # What is deliberately NOT matched
//!
//! **A `do { ... } while (...)` tail.** It ends with a balanced `while (...)`
//! and needs no body, and it is how nearly every `#define X do { ... }
//! while (0)` written inside a guard ends -- by far the most common spelling
//! of this text shape in the corpus (curl's `tool_setopt.h`, mosquitto's
//! vendored `uthash.h`/`utlist.h`, hostap's `fst_internal.h`, sel4's
//! `hardware.h`). Blanking those guards would be pure noise. A `while` whose
//! preceding token is `}` is therefore rejected.
//!
//! **The guard of a block the file proves is never compiled** (`#if 0`, see
//! `lang_parsing_substrate::dead_code_ranges`). There the header exists in
//! no configuration, so blanking the guard would make the statement after
//! the `#endif` the body of an `if` no build has, and every rule would read
//! dead code as live. Leaving the header in place is no better: two such
//! blocks in one function make tree-sitter's recovery fold the whole body
//! into one `ERROR`, inside which each header takes the live block as its
//! body again. So the header is blanked instead and the `#if 0` / `#endif`
//! pair is kept, which leaves a dead block with no header and a clean parse.
//! Blanking starts at the header's keyword, not its line: code before it on
//! that line (`} else if (z)`) may close what the block opened earlier. It
//! takes in a preceding `else` and every header the last one is the body of
//! (`if (a)` / `if (b)`), since neither has a body left once it is gone. A
//! block whose own braces do not pair up is left as it is: blanking part of
//! it can only hand one of its braces a partner in live code.
//!
//! **A backslash-continued macro body.** `#define CHECK(x) \` followed by
//! `if (x)` puts a header at the end of the block without putting a
//! statement there; the header belongs to the macro's replacement list, not
//! to the surrounding code.

use crate::analyze::init_state;
use crate::utility::cert_c::text_bounds;

/// The directive keyword on `line`, if it is one -- `"ifndef"` for both
/// `#ifndef X` and `# ifndef X`. The space after `#` is not cosmetic:
/// pure-ftpd indents nested conditionals exactly that way.
pub(crate) fn directive_keyword(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix('#')?;
    Some(
        rest.trim_start()
            .split(|c: char| !c.is_alphanumeric())
            .next()
            .unwrap_or(""),
    )
}

pub(crate) fn is_directive_start(line: &str) -> bool {
    matches!(directive_keyword(line), Some("if" | "ifdef" | "ifndef"))
}

pub(crate) fn is_endif(line: &str) -> bool {
    directive_keyword(line) == Some("endif")
}

pub(crate) fn is_branch_directive(line: &str) -> bool {
    matches!(directive_keyword(line), Some("else" | "elif"))
}

pub(crate) fn is_directive(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

/// Strip `//` and `/* ... */` comments so a trailing comment cannot hide the
/// `)` that ends a control header -- sqlite and mosquitto both write one
/// there.
pub(crate) fn strip_comments(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            match s[i + 2..].find("*/") {
                Some(j) => i += 2 + j + 2,
                None => break,
            }
        } else if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            match s[i..].find('\n') {
                Some(j) => i += j,
                None => break,
            }
        } else {
            // Multi-byte characters only occur inside comments and string
            // literals here; copying byte-wise would split them, so step by
            // character.
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Whether `content` ends with a control-flow header whose body must follow
/// it. See the module docs for the two shapes deliberately excluded.
pub(crate) fn ends_with_control_header(content: &str) -> bool {
    control_header_start(&strip_comments(content)).is_some()
}

/// `s` with every comment replaced by spaces, newlines kept, so a byte
/// offset into the result is one into `s`.
fn blank_comments(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0usize;
    while i < b.len() {
        let end = if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
            s[i + 2..].find("*/").map_or(b.len(), |j| i + 2 + j + 2)
        } else if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
            s[i..].find('\n').map_or(b.len(), |j| i + j)
        } else {
            i += 1;
            continue;
        };
        for c in &mut out[i..end] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
        i = end;
    }
    // Only whole comments were replaced, and each starts and ends on an
    // ASCII byte.
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// Where the control-flow header that comment-free `text` ends with starts:
/// the byte offset of its `if`/`while`/`for` keyword.
fn control_header_start(text: &str) -> Option<usize> {
    let t = text.trim_end();
    if !t.ends_with(')') {
        return None;
    }

    // Walk back to the `(` that opens the trailing group.
    let b = t.as_bytes();
    let mut depth = 0i32;
    let mut open = None;
    let mut i = b.len();
    while i > 0 {
        i -= 1;
        match b[i] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    open = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let open = open?;

    let head = t[..open].trim_end();
    let kw_start = head
        .char_indices()
        .rev()
        .find(|(_, c)| !(c.is_alphanumeric() || *c == '_'))
        .map_or(0, |(p, c)| p + c.len_utf8());

    let is_header = match &head[kw_start..] {
        "if" | "for" => true,
        // `} while (0)` closes a do-while; it governs nothing that follows.
        "while" => !head[..kw_start].trim_end().ends_with('}'),
        _ => false,
    };
    is_header.then_some(kw_start)
}

/// Where the code a dead block's trailing header governs nothing with
/// starts in comment-free `text`: the header's keyword, moved back over any
/// header it is itself the body of (`if (a)` / `if (b)`), then over an
/// `else` the first header continues.
fn dead_header_start(text: &str) -> Option<usize> {
    let mut start = control_header_start(text)?;
    while let Some(outer) = control_header_start(&text[..start]) {
        start = outer;
    }
    let before = text[..start].trim_end();
    if let Some(rest) = before.strip_suffix("else") {
        if !rest.ends_with(|c: char| c.is_alphanumeric() || c == '_') {
            start = rest.len();
        }
    }
    Some(start)
}

/// Whether the `{` and `}` in comment-free `text`, outside string and
/// character literals, pair up.
fn braces_balance(text: &str) -> bool {
    let mut depth = 0i32;
    let mut quote = None;
    let mut escaped = false;
    for c in text.chars() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q || c == '\n' {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

/// Blank the header a dead block ends with, lines `from..=last` holding its
/// code: from the header's start on its first line, every code line after
/// it whole. Code before the header on that first line stays, since it may
/// close what an earlier line of the block opened. A block whose own braces
/// do not pair up is left alone: blanking part of it can only move a live
/// brace's partner.
fn blank_dead_header(
    out: &mut [u8],
    lines: &[&str],
    line_starts: &[usize],
    from: usize,
    last: usize,
) {
    let mut joined = String::new();
    let mut at = Vec::new();
    for k in (from..=last).filter(|&k| !is_directive(lines[k])) {
        if !joined.is_empty() {
            joined.push('\n');
        }
        at.push((k, joined.len()));
        joined.push_str(lines[k]);
    }
    let text = blank_comments(&joined);
    if !braces_balance(&text) {
        return;
    }
    let Some(start) = dead_header_start(&text) else {
        return;
    };
    let Some(&(first, off)) = at.iter().rev().find(|&&(_, off)| off <= start) else {
        return;
    };
    let col = start - off;
    blank_line(out, line_starts[first] + col, lines[first].len() - col);
    for &(k, _) in at.iter().filter(|&&(k, _)| k > first) {
        blank_line(out, line_starts[k], lines[k].len());
    }
}

/// True when `idx` sits inside a backslash-continued sequence begun by a
/// preprocessor directive -- the replacement list of a multi-line `#define`
/// rather than a statement.
fn continues_a_directive(lines: &[&str], idx: usize) -> bool {
    let mut k = idx;
    while k > 0 && lines[k - 1].trim_end().ends_with('\\') {
        k -= 1;
        if is_directive(lines[k]) {
            return true;
        }
    }
    false
}

/// Blank the preprocessor directive lines that separate a control-flow header
/// from its body, per the module docs above. Length-preserving.
pub fn blank_control_header_guarded_preproc(source: &str) -> String {
    let (lines, line_starts) = text_bounds::lines_with_starts(source);

    let mut out = source.as_bytes().to_vec();
    let dead = init_state::file_proven_dead_lines(source);

    let mut i = 0usize;
    while i < lines.len() {
        if !is_directive_start(lines[i]) {
            i += 1;
            continue;
        }

        let mut depth = 1i32;
        let mut end_idx = None;
        let mut has_branch = false;
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
                has_branch = true;
            }
            j += 1;
        }

        let Some(end_idx) = end_idx else {
            // No matching #endif (truncated snippet, or unbalanced directives
            // elsewhere in the file) -- move on rather than halt the scan.
            i += 1;
            continue;
        };

        // An `#else`/`#elif` arm means the two arms are alternatives; blanking
        // the wrapper would splice both into one statement stream.
        // The line after the directive is 1-based `i + 2`.
        let in_dead = dead.iter().any(|&(s, e)| (s..=e).contains(&(i + 2)));
        if !has_branch {
            let last = (i + 1..end_idx)
                .rev()
                .find(|&k| !lines[k].trim().is_empty() && !is_directive(lines[k]));

            if let Some(last) = last {
                if !continues_a_directive(&lines, last) {
                    let content = joined_code(&lines, i + 1, last);
                    if ends_with_control_header(&content) {
                        if in_dead {
                            // The header exists in no build: blank it and
                            // keep the guard, so nothing becomes its body.
                            blank_dead_header(&mut out, &lines, &line_starts, i + 1, last);
                        } else {
                            blank_line(&mut out, line_starts[i], lines[i].len());
                            blank_line(&mut out, line_starts[end_idx], lines[end_idx].len());
                        }
                    }
                }
            }
        }

        // Advance by one line, not past `end_idx`: a nested `#if` inside this
        // block must still get its own independent check.
        i += 1;
    }

    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

/// The non-directive lines `from..=to`, joined.
fn joined_code(lines: &[&str], from: usize, to: usize) -> String {
    (from..=to)
        .filter(|&k| !is_directive(lines[k]))
        .map(|k| lines[k])
        .collect::<Vec<_>>()
        .join("\n")
}

/// Replace every non-newline byte of `line` (located at `line_start` in
/// `out`) with a space.
pub(crate) fn blank_line(out: &mut [u8], line_start: usize, line_len: usize) {
    for b in out.iter_mut().skip(line_start).take(line_len) {
        if *b != b'\n' && *b != b'\r' {
            *b = b' ';
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::c_language;

    fn parses_clean(src: &str) -> bool {
        let fixed = blank_control_header_guarded_preproc(src);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(&fixed, None).unwrap();
        !tree.root_node().has_error()
    }

    fn unchanged(src: &str) -> bool {
        blank_control_header_guarded_preproc(src) == src
    }

    #[test]
    fn fixes_if_split_from_its_brace() {
        // sqlite wherecode.c, sqlite3WhereExplainOneScan.
        let src = "\
int f(int x);
int g(void)
{
  int ret = 0;
#if !defined(SQLITE_DEBUG)
  if( f(1) || f(2) )
#endif
  {
    ret = 1;
  }
  return ret;
}
";
        assert!(parses_clean(src));
    }

    #[test]
    fn fixes_multi_line_condition() {
        let src = "\
int f(int x);
int g(void)
{
  int ret = 0;
# if defined(A)
  if( f(1)
   && f(2) )
# endif
  {
    ret = 1;
  }
  return ret;
}
";
        assert!(parses_clean(src));
    }

    #[test]
    fn fixes_for_and_while_headers() {
        let src = "\
int g(int n)
{
  int i, t = 0;
#ifdef A
  for( i = 0; i < n; i++ )
#endif
  {
    t += i;
  }
#ifdef B
  while( t > 0 )
#endif
  {
    t--;
  }
  return t;
}
";
        assert!(parses_clean(src));
    }

    #[test]
    fn leaves_do_while_tail_alone() {
        // The dominant spelling of this text shape in the corpus. Blanking
        // these guards would be pure noise.
        let src = "\
#ifdef A
#define CHECK(x) do { if (x) { } } while (0)
#endif
int g(void) { return 0; }
";
        assert!(unchanged(src));
    }

    #[test]
    fn leaves_do_while_tail_alone_when_body_is_on_its_own_line() {
        let src = "\
#ifdef A
#define CHECK(x)   \\
    do {           \\
        if (x) { } \\
    } while (0)
#endif
int g(void) { return 0; }
";
        assert!(unchanged(src));
    }

    #[test]
    fn leaves_continued_macro_body_alone() {
        // The header is the macro's replacement list, not a statement.
        let src = "\
#ifdef A
#define CHECK(x) \\
    if (x)
#endif
int g(void) { return 0; }
";
        assert!(unchanged(src));
    }

    #[test]
    fn leaves_complete_guarded_block_alone() {
        let src = "\
int f(int x);
int g(void)
{
  int ret = 0;
#ifdef A
  if( f(1) ) {
    ret = 1;
  }
#endif
  return ret;
}
";
        assert!(unchanged(src));
    }

    #[test]
    fn leaves_call_expression_tail_alone() {
        // Ends with `)`, but the token before the group is not a keyword.
        let src = "\
int f(int x);
int g(void)
{
#ifdef A
  f(1)
#endif
  ;
  return 0;
}
";
        assert!(unchanged(src));
    }

    #[test]
    fn leaves_alternative_arms_alone() {
        // Blanking a wrapper with an #else would splice both arms together.
        let src = "\
int f(int x);
int g(void)
{
  int ret = 0;
#ifdef A
  if( f(1) )
#else
  if( f(2) )
#endif
  {
    ret = 1;
  }
  return ret;
}
";
        assert!(unchanged(src));
    }

    #[test]
    fn trailing_comment_does_not_hide_the_header() {
        let src = "\
int f(int x);
int g(void)
{
  int ret = 0;
#ifdef A
  if( f(1) ) /* only when A */
#endif
  {
    ret = 1;
  }
  return ret;
}
";
        assert!(parses_clean(src));
    }

    #[test]
    fn blanks_only_the_header_in_a_dead_block() {
        // No build has the `if`, so `b++;` is not its body.
        let src = "\
int f(int a, int b)
{
#if 0
  if (a)
#endif
  b++;
  return b;
}
";
        let want = src.replace("  if (a)", &" ".repeat(8));
        assert_eq!(blank_control_header_guarded_preproc(src), want);
        assert!(parses_clean(src));
    }

    #[test]
    fn blanks_a_multi_line_dead_header_and_nothing_before_it() {
        let src = "\
int f(int a, int b)
{
#if 0
  a++;
  while( a
      && b )
#endif
  { b++; }
  return b;
}
";
        let want = src
            .replace("  while( a\n", "          \n")
            .replace("      && b )\n", "            \n");
        assert_eq!(blank_control_header_guarded_preproc(src), want);
        assert!(parses_clean(src));
    }

    #[test]
    fn two_dead_headers_in_one_function_parse_clean() {
        // Unblanked, recovery turns this whole body into one ERROR and
        // loses the `return`.
        let src = "\
int a(void);
int b(void);
int f(int p)
{
#if 0
  if (p)
#endif
  { a(); }
#if 0
  while (p)
#endif
  { b(); }
  return 0;
}
";
        assert!(parses_clean(src));
        let fixed = blank_control_header_guarded_preproc(src);
        assert_eq!(fixed.matches("#if 0").count(), 2);
        assert_eq!(fixed.matches("#endif").count(), 2);
    }

    #[test]
    fn keeps_what_a_dead_else_if_closes() {
        // Blanking the whole last line would drop the `}` that closes the
        // `{` two lines up, and the live block would close the function.
        let src = "\
int f(int x, int z, int n)
{
#if 0
  if (x) {
    n = 0;
  } else if (z)
#endif
  {
    n++;
  }
  return n;
}
";
        let want = src.replace("  } else if (z)\n", "  }            \n");
        assert_eq!(blank_control_header_guarded_preproc(src), want);
        assert!(parses_clean(src));
    }

    #[test]
    fn keeps_code_before_a_dead_header_on_its_line() {
        let src = "\
int g(int, int);
int f(int a, int b)
{
#if 0
  g(a,
    b); if (a)
#endif
  { b++; }
  return b;
}
";
        let want = src.replace("    b); if (a)\n", "    b);       \n");
        assert_eq!(blank_control_header_guarded_preproc(src), want);
        assert!(parses_clean(src));
    }

    #[test]
    fn blanks_every_dead_header_the_last_one_is_the_body_of() {
        let src = "\
int f(int a, int b)
{
#if 0
  if (a)
    if (b)
#endif
  b++;
#if 0
  for (;;) /* spin */
  while (a)
#endif
  { a++; }
  return b;
}
";
        let want = src
            .replace("  if (a)\n    if (b)\n", "        \n          \n")
            .replace(
                "  for (;;) /* spin */\n  while (a)\n",
                &format!("{}\n{}\n", " ".repeat(21), " ".repeat(11)),
            );
        assert_eq!(blank_control_header_guarded_preproc(src), want);
        assert!(parses_clean(src));
    }

    #[test]
    fn leaves_a_dead_block_with_unpaired_braces_alone() {
        let src = "\
void a(void);
void f(int x)
{
    if (x) {
#if 0
        }
        if (x)
#endif
        a();
    }
}
";
        assert!(unchanged(src));
    }

    #[test]
    fn is_length_preserving() {
        let src = "\
int f(int x);
int g(void)
{
#ifdef A
  if( f(1) )
#endif
  { return 1; }
  return 0;
}
";
        assert_eq!(blank_control_header_guarded_preproc(src).len(), src.len());
    }

    #[test]
    fn a_crlf_file_is_blanked_at_the_bytes_of_its_lf_copy() {
        let src = "\
#include <string.h>
int f(char *d, const char *s, int x, int z, int n)
{
#if 0
  if (x) {
    n = 0;
  } else if (z)
#endif
  {
    memcpy(d, s, n);
  }
  return n;
}
";
        let lf = blank_control_header_guarded_preproc(src);
        assert_ne!(lf, src, "the LF copy must trigger the pass");
        let crlf = src.replace('\n', "\r\n");
        assert_eq!(
            blank_control_header_guarded_preproc(&crlf),
            lf.replace('\n', "\r\n")
        );
        // A lone '\r' ends no line: one long line, left as it was or blanked
        // in place, never a panic.
        let cr = src.replace('\n', "\r");
        assert_eq!(blank_control_header_guarded_preproc(&cr).len(), cr.len());
    }
}
