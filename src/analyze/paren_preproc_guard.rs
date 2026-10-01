//! Pre-parse pass: blank a `#if`/`#ifdef`/`#ifndef` + matching `#endif` pair
//! that opens *inside* an unclosed parenthesized expression.
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
//! Deliberately conservative, and both conditions matter because the
//! "inside an unclosed paren" test is textual:
//!
//! * The guarded lines must contain no `;`, `{` or `}`. An expression
//!   fragment has none; a statement does. This is what keeps a
//!   *statement*-level guard from being blanked if the paren scan ever
//!   misjudges.
//! * The guarded lines' own parentheses must balance, so blanking the
//!   directives cannot leave the expression unbalanced.
//!
//! # A conditional with `#else`/`#elif` arms
//!
//! Real shape (pure-ftpd `ftpd.c`, `dopass`; the same file's `main` picks
//! `getopt_long` or `getopt` inside a `while` condition the same way):
//! ```c
//! if (
//! #if defined(WITH_LDAP) || defined(WITH_MYSQL) || ...
//!     doinitsupgroups(NULL, authresult.uid, authresult.gid) != 0
//! #else
//!     doinitsupgroups(account, (uid_t) -1, authresult.gid) != 0
//! #endif
//!     ) {
//! ```
//! Blanking only the directives would splice both arms into one expression,
//! `a != 0 b != 0`, which parses no better. So, as `preproc_split_chain`
//! does for a header split across a chain, one arm is kept and every other
//! arm's lines are blanked with the directives, each directive together with
//! its `\`-continuation lines. The kept arm is the one the scan's profile
//! compiles, conditions read in order (`preproc_arm_choice::compiled_arm`);
//! a conditional whose arm that cannot decide is left alone. Each arm must meet
//! both conditions above on its own, so what is kept is a whole operand and
//! what is dropped is an expression fragment: never a declaration or a
//! statement. An arm holding a directive of its own is left alone.
//!
//! Not inside a call's argument list, though: there the arms are what
//! PRE32-C reports (a directive in a function-like macro invocation is
//! undefined, and one in a real call reads the same), and blanking them
//! would leave it nothing to see. Only a parenthesis that is a controlling
//! expression or a grouping, as both of `ftpd.c`'s are, is repaired this
//! way.
//!
//! What that costs: the dropped arms' code leaves analysis, calls included
//! (`doinitsupgroups(NULL, ...)` above), where before it sat under an
//! `ERROR` node that rules still walked. What it buys, measured on the
//! shipped pipeline with the project prescan: unrepaired, this conditional
//! and the one in `main` left `ftpd.c`'s ROOT an `ERROR` node spanning the
//! whole file, with `dopass`'s header, braces and statements loose under it
//! and no `function_definition` around them, so a rule that reads a function
//! body did not see `dopass` at all. (A probe counting definitions under the
//! root's `ERROR` children misses this shape: the root is the `ERROR`.)

use crate::analyze::preproc_arm_choice::{compiled_arm, directive_extent, locally_defined_names};

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

/// Whether the innermost parenthesis still open before line `i` opens a
/// call's argument list: a name or a closing bracket stands before it, and
/// the name is not a keyword that takes a parenthesized expression.
///
/// Only asked once [`inside_unclosed_paren`] said some parenthesis is open,
/// over the same lines.
fn opens_call_arguments(lines: &CodeLines, i: usize) -> bool {
    let mut depth = 0i32;
    for k in (0..i).rev().take(MAX_STATEMENT_LOOKBACK) {
        // The same statement bounds as `inside_unclosed_paren`, so an
        // earlier statement's parentheses (or an earlier conditional's arms)
        // are never counted.
        if lines.raw[k].trim().is_empty() || lines.ends_statement(k) {
            return false;
        }
        let code = lines.code[k].as_bytes();
        for at in (0..code.len()).rev() {
            match code[at] {
                b')' => depth += 1,
                b'(' if depth > 0 => depth -= 1,
                b'(' => return precedes_call_arguments(&lines.code[..=k], k, at),
                _ => {}
            }
        }
    }
    false
}

/// Whether the `(` at `code[k][at]` follows something it would call.
fn precedes_call_arguments(code: &[String], k: usize, at: usize) -> bool {
    let before = code[..k]
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(&code[k][..at]))
        .collect::<Vec<_>>()
        .join("\n");
    let before = before.trim_end();
    if before.ends_with([')', ']']) {
        return true;
    }
    let word_start = before
        .rfind(|c: char| !(c.is_alphanumeric() || c == '_'))
        .map_or(0, |p| p + 1);
    let word = &before[word_start..];
    let is_name = word
        .chars()
        .next()
        .is_some_and(|c| c.is_alphabetic() || c == '_');
    is_name
        && !matches!(
            word,
            "if" | "while" | "for" | "switch" | "return" | "sizeof" | "_Alignof" | "_Generic"
        )
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
    let local = locally_defined_names(&lines.raw);

    for i in 0..lines.len() {
        if !is_directive_start(lines.raw[i]) || !inside_unclosed_paren(&lines, i) {
            continue;
        }

        let mut depth = 1i32;
        let mut end_idx = None;
        let mut branches = Vec::new();
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
                branches.push(j);
            }
        }

        let Some(end_idx) = end_idx else {
            continue; // No matching #endif -- move on rather than halt.
        };

        let mut edges = vec![i];
        edges.extend(branches.iter().copied());
        edges.push(end_idx);
        // An arm starts after its directive's `\`-continuation lines, which
        // are the directive's text, not the arm's.
        let arms: Vec<_> = edges
            .windows(2)
            .map(|e| directive_extent(&lines.raw, e[0]).end..e[1])
            .collect();
        let is_expression_fragment = |arm: &std::ops::Range<usize>| {
            arm.clone()
                .all(|k| !lines.code[k].contains([';', '{', '}']))
        };
        let balanced = |arm: &std::ops::Range<usize>| {
            arm.clone().map(|k| lines.paren_balance(k)).sum::<i32>() == 0
        };
        let has_code =
            |arm: &std::ops::Range<usize>| arm.clone().any(|k| !lines.code[k].trim().is_empty());
        let own_directive =
            |arm: &std::ops::Range<usize>| arm.clone().any(|k| is_directive(lines.raw[k]));
        if !arms
            .iter()
            .all(|a| is_expression_fragment(a) && balanced(a))
        {
            continue;
        }
        let kept = if branches.is_empty() {
            0
        } else {
            if opens_call_arguments(&lines, i)
                || !arms.iter().all(|a| has_code(a) && !own_directive(a))
            {
                continue;
            }
            let openers: Vec<usize> = std::iter::once(i).chain(branches.iter().copied()).collect();
            match compiled_arm(&lines.raw, &openers, &local) {
                Some(kept) => kept,
                None => continue,
            }
        };
        let dropped = arms
            .iter()
            .enumerate()
            .filter(|&(a, _)| a != kept)
            .flat_map(|(_, arm)| arm.clone());
        let directives = std::iter::once(i)
            .chain(branches.iter().copied())
            .chain(std::iter::once(end_idx))
            .flat_map(|d| directive_extent(&lines.raw, d));
        for k in directives.chain(dropped) {
            blank_line(&mut out, line_starts[k], lines.raw[k].len());
        }
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
    fn leaves_a_two_branch_block_in_call_arguments_alone() {
        // PRE32-C reports exactly this; the directives must survive.
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

    #[test]
    fn keeps_the_first_arm_of_an_ifndef_grouping() {
        // pure-ftpd ftpd.c, main's option loop: `option_index` is declared
        // under the same `#ifndef` and used only by the first arm.
        let src = "\
int getopt_long(int c, char **v, int *i);
int getopt(int c, char **v);
void f(int argc, char **argv) {
    int o;
#ifndef NO_GETOPT_LONG
    int option_index = 0;
#endif
    while ((o =
#ifndef NO_GETOPT_LONG
            getopt_long(argc, argv, &option_index)
#else
            getopt(argc, argv)
#endif
            ) != -1) {
        argc--;
    }
}
";
        let out = blank_paren_guarded_preproc(src);
        assert!(out.contains("getopt_long(argc, argv, &option_index)"));
        assert!(!out.contains("getopt(argc, argv)"));
        assert!(parses_clean(src));
        assert_eq!(out.len(), src.len());
    }

    #[test]
    fn fixes_a_two_branch_if_condition() {
        // pure-ftpd ftpd.c, dopass.
        let src = "\
int g(int a, int b);
void f(int u) {
    if (
#if defined(WITH_LDAP) || defined(WITH_MYSQL)
        g(u, 0) != 0
#elif defined(WITH_PGSQL)
        g(u, 2) != 0
#else
        g(u, 1) != 0
#endif
        ) {
        u = 0;
    }
}
";
        let out = blank_paren_guarded_preproc(src);
        assert!(out.contains("g(u, 1) != 0"));
        assert!(!out.contains("g(u, 0)") && !out.contains("g(u, 2)"));
        assert!(parses_clean(src));
    }

    #[test]
    fn keeps_the_first_arm_of_a_negated_defined_condition() {
        let src = "\
int g(int a);
void f(int u) {
    if (
#if !defined(NO_CHECK)
        g(u) != 0
#else
        0
#endif
        ) {
        u = 0;
    }
}
";
        let out = blank_paren_guarded_preproc(src);
        assert!(out.contains("g(u) != 0"));
        assert!(parses_clean(src));
    }

    #[test]
    fn leaves_a_conditional_whose_arm_cannot_be_decided_alone() {
        let src = "\
int g(int a);
void f(int u) {
    if (
#if LIB_VERSION(2, 1)
        g(u) != 0
#else
        0
#endif
        ) {
        u = 0;
    }
}
";
        assert_eq!(blank_paren_guarded_preproc(src), src);
    }

    #[test]
    fn blanks_a_comment_the_directive_leaves_open() {
        let src = "\
int g(int a);
void f(int u) {
    if (
#if !defined(A) /* start
   end */
        g(u) != 0
#else
        0
#endif
        ) {
        u = 0;
    }
}
";
        let out = blank_paren_guarded_preproc(src);
        assert!(!out.contains("end */"));
        assert!(out.contains("g(u) != 0"));
        assert!(parses_clean(src));
    }

    #[test]
    fn keeps_what_the_preprocessor_keeps_after_a_directive_s_comment() {
        // `g(u)` follows the `*/` of a comment `#else` opened, so it is
        // extra tokens on the `#else` line, which `gcc -E` drops too.
        let src = "\
int g(int a);
void f(int u) {
    if (
#ifdef A
        0
#else /* c
   */ g(u)
        u
#endif
        != 0) {
        u = 0;
    }
}
";
        let out = blank_paren_guarded_preproc(src);
        assert!(!out.contains("g(u)"));
        assert!(!out.contains("        0\n"));
        assert!(out.contains("        u\n"));
        assert!(parses_clean(src));
    }

    #[test]
    fn blanks_a_directive_with_its_continuation_lines() {
        let src = "\
int g(int a);
void f(int u) {
    if (
#if defined(A) || \\
    defined(B)
        g(u) != 0
#elif defined(C) && \\
    defined(D)
        g(u) != 1
#else
        g(u) != 2
#endif
        ) {
        u = 0;
    }
}
";
        let out = blank_paren_guarded_preproc(src);
        assert!(!out.contains("defined"));
        assert!(out.contains("g(u) != 2"));
        assert!(!out.contains("g(u) != 0") && !out.contains("g(u) != 1"));
        assert!(parses_clean(src));
    }

    #[test]
    fn leaves_a_branch_holding_its_own_directive_alone() {
        let src = "\
void f(void) {
    foo(a &&
#ifdef A
# ifdef B
        b
# endif
        c
#else
        0
#endif
        );
}
";
        // The inner single-arm guard is repaired on its own; the outer
        // block, whose first arm held it, keeps both arms and directives.
        let out = blank_paren_guarded_preproc(src);
        assert!(out.contains("#ifdef A\n") && out.contains("#else\n"));
        assert!(out.contains("        b\n") && out.contains("        0\n"));
    }

    #[test]
    fn leaves_a_branch_holding_a_statement_alone() {
        let src = "\
void f(void) {
    foo(a,
#ifdef A
        b);
    bar(
#else
        c
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
