//! Pre-parse pass: blank a `#if`/`#ifdef`/`#ifndef` + matching `#endif` pair
//! that opens *inside* an unclosed parenthesized expression (task 1044).
//!
//! Real shape (pure-ftpd `ls.c`, `listfile`):
//! ```c
//! if (
//! # ifndef ALWAYS_SHOW_RESOLVED_SYMLINKS
//!     broken_client_compat != 0 &&
//! # endif
//!     S_ISLNK(st.st_mode)) {
//! ```
//!
//! and, equivalently, a build-time-optional operand of a condition
//! (sqlite `alter.c`, `os_unix.c`, curl `url.c`) or a build-time-optional
//! entry in a parameter or argument list.
//!
//! `tree-sitter-c` has no production for a preprocessor conditional inside
//! an expression -- `preproc_if` is a *block item*, so it can sit between
//! statements but never between two operands -- and there is no error
//! recovery that isolates it cleanly. Every occurrence of this shape is a
//! parse error, confirmed across the condition, parameter-list and
//! argument-list spellings.
//!
//! What makes it worth a pass of its own is how *unstably* the parse fails.
//! GLR recovery picks between competing repairs by cost, and the cost
//! depends on the tokens that follow, so an edit far away flips the outcome:
//! on pure-ftpd's `ls.c`, truncated after `listfile` and padded with a
//! filler function, sixteen trivial statements of padding leave `listfile`
//! parsed as a normal `function_definition` and seventeen collapse
//! everything from its opening line to end-of-file into a single `ERROR`
//! node -- a one-statement, 16-byte difference. Inside that node the
//! function's *definition* is invisible to every rule that walks the tree
//! (DCL31-C then reports each later call to `listfile` as undeclared) while
//! its calls are still found, which is the worst of both. The threshold is a
//! parser-internal artifact, so the same file is fine or broken depending on
//! edits with nothing to do with it.
//!
//! Fix, mirroring `preproc_dangling_else` and `label_preproc_guard`: blank
//! the opening directive line and its matching `#endif` (same-length
//! whitespace, newlines preserved), so the guarded fragment rejoins the
//! expression it belongs to. The cost is the same one those passes accept --
//! aurora-lint's "maybe compiled" `#ifdef` branch modeling
//! (`process_preproc_conditional` in `analyze::cfg`) is lost for this
//! fragment. Here that cost is close to zero: the fragment currently sits
//! inside an `ERROR` node, so no rule was reading a `preproc_ifdef` ancestor
//! off it in the first place.
//!
//! Deliberately conservative, and all three conditions matter because the
//! "inside an unclosed paren" test is textual:
//!
//! * The block must have no `#else`/`#elif` at its own depth -- keeping one
//!   branch's text would silently pick a side of a two-sided expression
//!   (the same call the passes above make).
//! * The guarded lines must contain no `;`, `{` or `}`. An expression
//!   fragment has none; a statement does. This is what keeps a
//!   *statement*-level guard from being blanked if the paren scan ever
//!   misjudges.
//! * The guarded lines' own parentheses must balance, so blanking the
//!   directives cannot leave the expression unbalanced.

/// How far back the paren scan will look for the start of the statement
/// containing a directive. Bounded so a pathological file cannot make this
/// quadratic, and because a parenthesized expression spanning more lines
/// than this is not a shape worth guessing about.
const MAX_STATEMENT_LOOKBACK: usize = 64;

/// The directive keyword on `line`, if it is one -- `"ifndef"` for both
/// `#ifndef X` and `# ifndef X`. The space after `#` is not cosmetic here:
/// pure-ftpd indents nested conditionals exactly that way (`# ifndef ...`
/// inside an `#if`), which is the very file this pass exists for.
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

/// Per-line view of a file with comments and literals removed, so a `(`,
/// `;` or `}` counted below is always real code.
struct CodeLines<'a> {
    raw: Vec<&'a str>,
    /// `raw[i]` with comments, string and character literals replaced by
    /// spaces. Preprocessor directive lines (including `\`-continuations)
    /// are blank here: their parentheses are the directive's own.
    code: Vec<String>,
}

impl<'a> CodeLines<'a> {
    fn new(source: &'a str) -> Self {
        let raw: Vec<&str> = source.lines().collect();
        let mut code = Vec::with_capacity(raw.len());
        let mut in_block_comment = false;
        let mut in_directive = false;
        for line in &raw {
            let (stripped, still_open) = strip_comments_and_literals(line, in_block_comment);
            in_block_comment = still_open;
            let is_directive_line = in_directive || is_directive(line);
            // A directive continues onto the next physical line via a
            // trailing `\`, and that continuation is still the directive's
            // text, not code.
            in_directive = is_directive_line && line.trim_end().ends_with('\\');
            code.push(if is_directive_line {
                " ".repeat(stripped.len())
            } else {
                stripped
            });
        }
        Self { raw, code }
    }

    fn len(&self) -> usize {
        self.raw.len()
    }

    fn paren_balance(&self, i: usize) -> i32 {
        let line = &self.code[i];
        line.matches('(').count() as i32 - line.matches(')').count() as i32
    }

    /// True if line `i` closes a statement, i.e. its code ends with `;`,
    /// `{` or `}`. Used only as a backward-scan stopping point.
    fn ends_statement(&self, i: usize) -> bool {
        matches!(
            self.code[i].trim_end().chars().next_back(),
            Some(';' | '{' | '}')
        )
    }
}

/// Replace every comment, string literal and character literal in `line`
/// with spaces, preserving length. Returns the stripped line and whether a
/// block comment is still open at end of line.
fn strip_comments_and_literals(line: &str, mut in_block_comment: bool) -> (String, bool) {
    let bytes = line.as_bytes();
    let mut out = vec![b' '; bytes.len()];
    let mut i = 0usize;
    while i < bytes.len() {
        if in_block_comment {
            if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                in_block_comment = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                in_block_comment = true;
                i += 2;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => break,
            quote @ (b'"' | b'\'') => {
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == quote {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            c => {
                out[i] = c;
                i += 1;
            }
        }
    }
    // Safe: every retained byte came from `line` at the same index and is
    // ASCII (a multi-byte sequence only ever appears inside a comment or a
    // string literal, both of which are blanked wholesale here), and every
    // other byte is an ASCII space.
    (
        String::from_utf8(out).unwrap_or_else(|_| " ".repeat(bytes.len())),
        in_block_comment,
    )
}

/// True if line `i` sits inside a parenthesized expression that opened
/// earlier in the same statement.
///
/// Counted backwards from the statement's own start rather than tracked
/// forward across the file on purpose: a `#if`/`#else` pair whose two
/// branches contain different numbers of parentheses (sqlite has several)
/// makes a whole-file running count drift, and a drifted count would report
/// ordinary statement-level guards hundreds of lines later as being inside
/// an expression.
fn inside_unclosed_paren(lines: &CodeLines, i: usize) -> bool {
    let mut balance = 0i32;
    let mut scanned = 0usize;
    let mut k = i;
    while k > 0 && scanned < MAX_STATEMENT_LOOKBACK {
        k -= 1;
        scanned += 1;
        // A blank line is treated as a statement boundary: it bounds the
        // scan cheaply and no real parenthesized expression is split by
        // one. A comment-only line contributes nothing and is not a
        // boundary.
        if lines.raw[k].trim().is_empty() {
            break;
        }
        balance += lines.paren_balance(k);
        if lines.ends_statement(k) {
            break;
        }
    }
    balance > 0
}

/// Blank the `#if`/`#ifdef`/`#ifndef` + matching `#endif` directive lines of
/// every conditional that opens inside an unclosed parenthesized
/// expression, per the module docs above. Length-preserving.
pub fn blank_paren_guarded_preproc(source: &str) -> String {
    let lines = CodeLines::new(source);
    let mut line_starts = Vec::with_capacity(lines.len());
    let mut offset = 0usize;
    for line in &lines.raw {
        line_starts.push(offset);
        offset += line.len() + 1; // '\n' (a CRLF's '\r' is left as-is below)
    }

    let mut out = source.as_bytes().to_vec();

    for i in 0..lines.len() {
        if !is_directive_start(lines.raw[i]) || !inside_unclosed_paren(&lines, i) {
            continue;
        }

        let mut depth = 1i32;
        let mut end_idx = None;
        let mut has_branch = false;
        for (j, raw) in lines.raw.iter().enumerate().skip(i + 1) {
            if is_directive_start(raw) {
                depth += 1;
            } else if is_endif(raw) {
                depth -= 1;
                if depth == 0 {
                    end_idx = Some(j);
                    break;
                }
            } else if depth == 1 && is_branch_directive(raw) {
                has_branch = true;
            }
        }

        let Some(end_idx) = end_idx else {
            continue; // No matching #endif -- move on rather than halt.
        };
        if has_branch {
            continue;
        }

        let body = i + 1..end_idx;
        let is_expression_fragment = body
            .clone()
            .all(|k| !lines.code[k].contains([';', '{', '}']));
        let balanced = body.clone().map(|k| lines.paren_balance(k)).sum::<i32>() == 0;
        if !is_expression_fragment || !balanced {
            continue;
        }

        blank_line(&mut out, line_starts[i], lines.raw[i].len());
        blank_line(&mut out, line_starts[end_idx], lines.raw[end_idx].len());
    }

    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

/// Replace every non-newline byte of the line at `line_start` with a space.
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

    fn fixed(src: &str) -> String {
        let out = blank_paren_guarded_preproc(src);
        assert_eq!(src.len(), out.len(), "byte length changed");
        assert_eq!(
            src.matches('\n').count(),
            out.matches('\n').count(),
            "line count changed"
        );
        out
    }

    fn parses_clean(src: &str) -> bool {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(fixed(src), None).unwrap();
        !tree.root_node().has_error()
    }

    #[test]
    fn fixes_ifdef_splitting_an_if_condition() {
        let src = "\
int f(int a, int b) {
    if (a
#ifdef X
        && b
#endif
        ) {
        return 1;
    }
    return 0;
}
";
        assert!(parses_clean(src));
        assert!(!fixed(src).contains("#ifdef X"));
    }

    /// pure-ftpd indents a nested conditional as `# ifndef X`, which is the
    /// spelling this pass was written for.
    #[test]
    fn fixes_a_space_between_hash_and_keyword() {
        let src = "\
int f(int a) {
    if (
# ifndef ALWAYS_SHOW_RESOLVED_SYMLINKS
        compat != 0 &&
# endif
        g(a)) {
        return 1;
    }
    return 0;
}
";
        assert!(parses_clean(src));
    }

    #[test]
    fn fixes_ifdef_in_a_parameter_list() {
        let src = "\
static void g(
#ifdef X
    int a,
#endif
    int b)
{
}
";
        assert!(parses_clean(src));
    }

    #[test]
    fn fixes_ifdef_in_an_argument_list() {
        let src = "\
void h(void) {
    foo(1,
#ifdef X
        2,
#endif
        3);
}
";
        assert!(parses_clean(src));
    }

    /// The common, already-parseable case: a guard around whole statements.
    /// tree-sitter handles it, and blanking it would throw away the
    /// `preproc_ifdef` node rules correlate against.
    #[test]
    fn leaves_a_statement_level_guard_alone() {
        let src = "\
void f(void) {
    int x = 0;
#ifdef X
    x = 1;
#endif
    (void) x;
}
";
        assert_eq!(blank_paren_guarded_preproc(src), src);
    }

    /// Keeping one branch of a two-sided expression would silently pick a
    /// side; leave it for the parser to fail on as before.
    #[test]
    fn leaves_a_two_branch_block_alone() {
        let src = "\
void f(void) {
    foo(a &&
#ifdef DEBUGBUILD
        getenv(\"X\")
#else
        0
#endif
        );
}
";
        assert_eq!(blank_paren_guarded_preproc(src), src);
    }

    /// Blanking the directives around a guarded fragment whose own
    /// parentheses do not balance would leave the expression unbalanced.
    #[test]
    fn leaves_an_unbalanced_body_alone() {
        let src = "\
void f(void) {
    foo(a,
#ifdef X
        bar(b,
#endif
        c));
}
";
        assert_eq!(blank_paren_guarded_preproc(src), src);
    }

    /// The reason the paren scan runs backwards from the statement rather
    /// than forwards across the file: the `#if`/`#else` pair below leaves a
    /// whole-file running count one `(` ahead forever, which would report
    /// the ordinary statement-level guard after it as being inside an
    /// expression.
    #[test]
    fn a_branch_with_unbalanced_parens_does_not_poison_later_guards() {
        let src = "\
void f(int a) {
#ifdef X
    g((a);
#else
    g(a));
#endif
    int x = 0;
#ifdef Y
    x = 1;
#endif
    (void) x;
}
";
        assert_eq!(blank_paren_guarded_preproc(src), src);
    }

    #[test]
    fn a_guard_inside_a_comment_or_string_is_not_a_directive() {
        let src = "\
void f(void) {
    const char *s = \"#ifdef X\";
    /* #ifdef Y */
    foo(s);
}
";
        assert_eq!(blank_paren_guarded_preproc(src), src);
    }
}
