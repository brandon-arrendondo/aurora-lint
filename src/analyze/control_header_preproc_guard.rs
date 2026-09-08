//! Pre-parse pass: blank a `#if`/`#ifdef`/`#ifndef` + matching `#endif` pair
//! whose guarded block ends with a control-flow HEADER -- `if (...)`,
//! `while (...)` or `for (...)` -- leaving the statement that header governs
//! on the far side of the `#endif` (task 1066).
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
//! **A backslash-continued macro body.** `#define CHECK(x) \` followed by
//! `if (x)` puts a header at the end of the block without putting a
//! statement there; the header belongs to the macro's replacement list, not
//! to the surrounding code.

/// The directive keyword on `line`, if it is one -- `"ifndef"` for both
/// `#ifndef X` and `# ifndef X`. The space after `#` is not cosmetic:
/// pure-ftpd indents nested conditionals exactly that way.
fn directive_keyword(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix('#')?;
    Some(
        rest.trim_start()
            .split(|c: char| !c.is_alphanumeric())
            .next()
            .unwrap_or(""),
    )
}

fn is_directive_start(line: &str) -> bool {
    matches!(directive_keyword(line), Some("if" | "ifdef" | "ifndef"))
}

fn is_endif(line: &str) -> bool {
    directive_keyword(line) == Some("endif")
}

fn is_branch_directive(line: &str) -> bool {
    matches!(directive_keyword(line), Some("else" | "elif"))
}

fn is_directive(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

/// Strip `//` and `/* ... */` comments so a trailing comment cannot hide the
/// `)` that ends a control header -- sqlite and mosquitto both write one
/// there.
fn strip_comments(s: &str) -> String {
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
fn ends_with_control_header(content: &str) -> bool {
    let stripped = strip_comments(content);
    let t = stripped.trim_end();
    if !t.ends_with(')') {
        return false;
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
    let Some(open) = open else {
        return false;
    };

    let head = t[..open].trim_end();
    let kw_start = head
        .char_indices()
        .rev()
        .find(|(_, c)| !(c.is_alphanumeric() || *c == '_'))
        .map_or(0, |(p, c)| p + c.len_utf8());

    match &head[kw_start..] {
        "if" | "for" => true,
        // `} while (0)` closes a do-while; it governs nothing that follows.
        "while" => !head[..kw_start].trim_end().ends_with('}'),
        _ => false,
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
        if !has_branch {
            let last = (i + 1..end_idx)
                .rev()
                .find(|&k| !lines[k].trim().is_empty() && !is_directive(lines[k]));

            if let Some(last) = last {
                if !continues_a_directive(&lines, last) {
                    let content = (i + 1..=last)
                        .filter(|&k| !is_directive(lines[k]))
                        .map(|k| lines[k])
                        .collect::<Vec<_>>()
                        .join("\n");
                    if ends_with_control_header(&content) {
                        blank_line(&mut out, line_starts[i], lines[i].len());
                        blank_line(&mut out, line_starts[end_idx], lines[end_idx].len());
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

/// Replace every non-newline byte of `line` (located at `line_start` in
/// `out`) with a space.
fn blank_line(out: &mut [u8], line_start: usize, line_len: usize) {
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
}
