//! Pre-parse pass: blank a `#if`/`#ifdef`/`#ifndef` + matching `#endif` pair
//! that sits between the entries of a brace initializer list.
//!
//! Real shape (mbedtls `ssl_tls12_server.c`, `ssl_parse_client_hello`):
//! ```c
//!         const uint16_t default_sig_algs[] = {
//! #if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
//!             MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_ECDSA,
//!                                                MBEDTLS_SSL_HASH_SHA1),
//! #endif
//! #if defined(MBEDTLS_RSA_C)
//!             MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_RSA,
//!                                                MBEDTLS_SSL_HASH_SHA1),
//! #endif
//!             MBEDTLS_TLS_SIG_NONE
//!         };
//! ```
//!
//! `tree-sitter-c` has a production for a conditional among statements, among
//! struct members and among enumerators, but none among the entries of an
//! `initializer_list`. What recovery does with one depends on where the
//! initializer is:
//!
//! * At file scope each directive becomes a small `ERROR` inside the list and
//!   the entries around it still parse.
//! * Inside a function body the declaration itself is lost. The first `#if`
//!   is read as a block-level `preproc_if` that runs to the end of the
//!   function body, with a synthesized `MISSING` `#endif`, and the function's
//!   closing brace is stranded.
//!
//! Worse, the outcome is not local. GLR recovery is global and cost-based, so
//! once the rest of a file parses cleanly the cheapest repair can wrap the
//! whole file in one `ERROR` around this damage. In mbedtls's
//! `ssl_tls12_server.c` it took all 48 function definitions, and every call
//! edge out of `ssl_parse_client_hello`, out of the tree every rule walks.
//! Blanking these four directives alone leaves the file with no top-level
//! `ERROR`.
//!
//! Fix, mirroring `paren_preproc_guard`: blank the conditional's directive
//! lines (same-length whitespace, newlines kept), so its entries rejoin the
//! list they belong to.
//!
//! * A conditional with one arm keeps that arm whatever its condition says,
//!   as `paren_preproc_guard` does: `#if 0` entries are analysed as if
//!   compiled. Blanking only the directives already produces a valid list.
//! * A conditional with `#else`/`#elif` arms keeps EVERY arm when a comma
//!   separates each arm's entries from the next arm's, so blanking only the
//!   directives leaves a valid list: `#ifdef A` / `x,` / `#else` / `y,` /
//!   `#endif` reads `x, y,`. Every arm some configuration compiles is
//!   reported as written (ADR-0010 Decision 1), so a rule that reads entries
//!   one at a time sees each alternative; keeping only the arm the scan's
//!   profile compiles dropped a labeled true positive in the arm it did not
//!   keep. The list as a whole is then no build's list: its element count
//!   and its contents mix configurations that exclude each other.
//! * Arms with no comma between them (`#ifdef A` / `PAIR(1, 2)` / `#else` /
//!   `PAIR(3, 4)` / `#endif`) would splice into `PAIR(1, 2) PAIR(3, 4)`, which
//!   does not parse. There the arm the scan's profile compiles is kept
//!   (`preproc_arm_choice::compiled_arm`) and the others are blanked, the
//!   cost `paren_preproc_guard` accepts for the same reason. A conditional
//!   whose arm cannot be decided is left alone.
//! * A multi-arm conditional whose arms hold directives of their own is left
//!   alone either way.
//!
//! The brace the conditional sits in must be an initializer's. That is read
//! from the code before it: a `{` right after `=` opens an initializer list,
//! and so does a `{` after `,` or `{` inside one (a nested aggregate). Any
//! other `{` opens something else, a function body, a struct or enum body or
//! a compound literal, and conditionals there are left to the other passes
//! or to the grammar. The open braces are tracked forward through the file,
//! with every arm of a conditional read from the brace depth its `#if` began
//! at, and the depth after the first arm carried past its `#endif`. A
//! whole-file count with each arm counted in turn would drift wherever arms
//! open different numbers of braces.
//!
//! Each arm must also be a run of whole entries:
//!
//! * no `;`, which an entry never holds and a statement always does;
//! * balanced braces and parentheses, so blanking cannot leave the list
//!   unbalanced;
//! * and the conditional must not sit inside a parenthesis opened within the
//!   list (`MACRO(a,` / `#if` / `b,` / `#endif` / `c)`). There the directive
//!   is in a macro invocation's arguments, which is PRE32-C's to report, and
//!   blanking it would leave that rule nothing to see.
//!
//! What it costs, as for the sibling passes: the "maybe compiled" modelling
//! of an `#ifdef` (`process_preproc_conditional` in `analyze::cfg`) is lost
//! for these entries. Nothing read it: before the repair they sat in an
//! `ERROR` node or outside the declaration altogether.

use crate::analyze::paren_preproc_guard::{
    blank_line, is_branch_directive, is_directive, is_directive_start, is_endif, CodeLines,
};
use crate::analyze::preproc_arm_choice::{compiled_arm, directive_extent, locally_defined_names};

/// One open `{`, as the forward scan tracks it.
#[derive(Clone, Copy)]
struct Brace {
    /// The brace opens an initializer list, or an aggregate nested in one.
    initializer: bool,
    /// The parenthesis depth when it opened. A conditional deeper than this
    /// is inside a parenthesis within the braces, not between entries.
    paren_depth: i32,
}

/// What the scan knows at a point in the file.
#[derive(Clone)]
struct ScanState {
    braces: Vec<Brace>,
    paren_depth: i32,
    /// The last non-blank code character, across lines.
    last_code: Option<char>,
}

impl ScanState {
    fn between_initializer_entries(&self) -> bool {
        self.braces
            .last()
            .is_some_and(|b| b.initializer && b.paren_depth == self.paren_depth)
    }

    fn read(&mut self, code: &str) {
        for c in code.chars() {
            match c {
                '{' => {
                    let initializer = match self.last_code {
                        Some('=') => true,
                        Some(',' | '{') => self.between_initializer_entries(),
                        _ => false,
                    };
                    self.braces.push(Brace {
                        initializer,
                        paren_depth: self.paren_depth,
                    });
                }
                '}' => {
                    // A `}` closes whatever parentheses its braces left open,
                    // so one malformed line cannot skew the rest of the file.
                    if let Some(b) = self.braces.pop() {
                        self.paren_depth = b.paren_depth;
                    }
                }
                '(' => self.paren_depth += 1,
                ')' => self.paren_depth = (self.paren_depth - 1).max(0),
                _ => {}
            }
            if !c.is_whitespace() {
                self.last_code = Some(c);
            }
        }
    }
}

/// An open conditional: where it started, the state its arms start from, the
/// state its first arm ended in, and whether it opened between entries.
struct OpenConditional {
    start: usize,
    branches: Vec<usize>,
    at_start: ScanState,
    after_first_arm: Option<ScanState>,
    in_initializer: bool,
}

/// A conditional the scan found opening between an initializer's entries.
struct Conditional {
    start: usize,
    branches: Vec<usize>,
    end: usize,
}

/// Every complete conditional that opens between the entries of an
/// initializer list, in one forward pass.
fn initializer_conditionals(lines: &CodeLines) -> Vec<Conditional> {
    let mut found = Vec::new();
    let mut state = ScanState {
        braces: Vec::new(),
        paren_depth: 0,
        last_code: None,
    };
    let mut open: Vec<OpenConditional> = Vec::new();
    for i in 0..lines.len() {
        let raw = lines.raw[i];
        if lines.starts_in_comment[i] || !is_directive(raw) {
            state.read(&lines.code[i]);
            continue;
        }
        if is_directive_start(raw) {
            open.push(OpenConditional {
                start: i,
                branches: Vec::new(),
                at_start: state.clone(),
                after_first_arm: None,
                in_initializer: state.between_initializer_entries(),
            });
        } else if is_branch_directive(raw) {
            if let Some(c) = open.last_mut() {
                c.branches.push(i);
                if c.after_first_arm.is_none() {
                    c.after_first_arm = Some(state.clone());
                }
                state = c.at_start.clone();
            }
        } else if is_endif(raw) {
            if let Some(c) = open.pop() {
                if let Some(first) = c.after_first_arm {
                    state = first;
                }
                if c.in_initializer {
                    found.push(Conditional {
                        start: c.start,
                        branches: c.branches,
                        end: i,
                    });
                }
            }
        }
    }
    found
}

/// Whether the lines of `arm` are whole initializer entries: no `;`, and
/// braces and parentheses that balance without ever closing more than they
/// opened.
fn is_entry_run(lines: &CodeLines, arm: &std::ops::Range<usize>) -> bool {
    let (mut braces, mut parens) = (0i32, 0i32);
    for k in arm.clone() {
        for c in lines.code[k].chars() {
            match c {
                ';' => return false,
                '{' => braces += 1,
                '}' => braces -= 1,
                '(' => parens += 1,
                ')' => parens -= 1,
                _ => {}
            }
            if braces < 0 || parens < 0 {
                return false;
            }
        }
    }
    braces == 0 && parens == 0
}

/// Whether every arm's entries are separated from the next non-empty arm's by
/// exactly one comma, at the end of the one or the start of the other, so
/// the arms read as one list once the directives are blank. Where both have
/// one, the splice would read `x,, y`.
///
/// Judged on the arms' own text with comments removed and literals kept: an
/// arm `"b",` begins with a string, not a comma, and an arm holding only
/// `"ab"` is an entry, not nothing.
fn arms_splice(lines: &CodeLines, arms: &[std::ops::Range<usize>]) -> bool {
    let code: Vec<String> = arms
        .iter()
        .map(|arm| {
            let text = arm
                .clone()
                .map(|k| lines.raw[k])
                .collect::<Vec<_>>()
                .join("\n");
            without_comments(&text).trim().to_string()
        })
        .filter(|c| !c.is_empty())
        .collect();
    code.windows(2)
        .all(|w| w[0].ends_with(',') != w[1].starts_with(','))
}

/// `text` with every comment replaced by a space and every string and
/// character literal kept as written.
fn without_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = '\0';
                for d in chars.by_ref() {
                    if prev == '*' && d == '/' {
                        break;
                    }
                    prev = d;
                }
                out.push(' ');
            }
            '/' if chars.peek() == Some(&'/') => {
                for d in chars.by_ref() {
                    if d == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '"' | '\'' => {
                out.push(c);
                while let Some(d) = chars.next() {
                    out.push(d);
                    if d == '\\' {
                        if let Some(e) = chars.next() {
                            out.push(e);
                        }
                    } else if d == c || d == '\n' {
                        break;
                    }
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Blank every conditional that sits between the entries of a brace
/// initializer list: its directives, and for a multi-arm one that does not
/// splice, every arm but the compiled one. Length- and line-preserving; a
/// no-op on a file without the construct.
pub fn blank_initializer_guarded_preproc(source: &str) -> String {
    let lines = CodeLines::new(source);
    let mut out = source.as_bytes().to_vec();
    let mut local = None;

    for c in initializer_conditionals(&lines) {
        let edges: Vec<usize> = std::iter::once(c.start)
            .chain(c.branches.iter().copied())
            .chain(std::iter::once(c.end))
            .collect();
        // An arm starts after its directive's `\`-continuation lines.
        let arms: Vec<_> = edges
            .windows(2)
            .map(|e| directive_extent(&lines.raw, e[0]).end..e[1])
            .collect();
        if !arms.iter().all(|a| is_entry_run(&lines, a)) {
            continue;
        }
        // `None` keeps every arm.
        let kept = if c.branches.is_empty() {
            None
        } else {
            let own_directive = |arm: &std::ops::Range<usize>| {
                arm.clone()
                    .any(|k| !lines.starts_in_comment[k] && is_directive(lines.raw[k]))
            };
            if arms.iter().any(own_directive) {
                continue;
            }
            if arms_splice(&lines, &arms) {
                None
            } else {
                let local = local.get_or_insert_with(|| locally_defined_names(&lines.raw));
                match compiled_arm(&lines.raw, &edges[..edges.len() - 1], local) {
                    Some(kept) => Some(kept),
                    None => continue,
                }
            }
        };
        let dropped = arms
            .iter()
            .enumerate()
            .filter(|&(a, _)| kept.is_some_and(|k| k != a))
            .flat_map(|(_, arm)| arm.clone());
        let directives = edges.iter().flat_map(|&d| directive_extent(&lines.raw, d));
        for k in directives.chain(dropped) {
            blank_line(&mut out, lines.starts[k], lines.raw[k].len());
        }
    }

    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::c_language;

    fn fixed(src: &str) -> String {
        let out = blank_initializer_guarded_preproc(src);
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
        let tree = parser.parse(src, None).unwrap();
        !tree.root_node().has_error()
    }

    #[test]
    fn fixes_single_arm_conditionals_in_a_local_initializer() {
        let src = "\
int f(int x)
{
    const int local[] = {
#if defined(A)
        MK(1,
           2),
#endif
#ifdef B
        3,
#endif
        0
    };
    return local[x];
}
";
        assert!(!parses_clean(src));
        let out = fixed(src);
        assert!(parses_clean(&out), "{out}");
        assert!(out.contains("MK(1,") && out.contains("3,"));
        assert!(!out.contains("#if") && !out.contains("#endif"));
    }

    #[test]
    fn fixes_a_file_scope_table_and_a_nested_aggregate() {
        let src = "\
struct pair { int a, b; };
static const struct pair tbl[] = {
    { 1, 2 },
#ifndef NO_THREE
    { 3, 4 },
#endif
    { .a = 5,
#if defined(B)
      .b = 6,
#endif
    },
};
";
        let out = fixed(src);
        assert!(parses_clean(&out), "{out}");
        assert!(out.contains("{ 3, 4 },") && out.contains(".b = 6,"));
    }

    #[test]
    fn keeps_every_arm_of_comma_separated_alternatives() {
        let src = "\
static const int tbl[] = {
#ifdef UNDECLARED_FEATURE
    1, 2,
#elif FOO_VERSION >= 3
    3,
#else
#endif
    4
#ifdef OTHER_FEATURE
    , 5
#else
    , 6
#endif
};
";
        let out = fixed(src);
        assert!(parses_clean(&out), "{out}");
        assert!(out.contains("1, 2,") && out.contains("3,"));
        assert!(out.contains(", 5") && out.contains(", 6"));
        assert!(!out.contains('#'));
    }

    #[test]
    fn a_comma_on_both_sides_of_an_arm_boundary_does_not_splice() {
        // Each configuration is valid (`0, 1,` and `0, 2`); the splice would
        // read `0, 1, , 2`.
        let src = "\
static const int tbl[] = {
    0
#ifdef UNDECLARED_FEATURE
    , 1,
#else
    , 2
#endif
};
";
        let out = fixed(src);
        assert!(parses_clean(&out), "{out}");
        assert!(!out.contains(", 1,"), "the compiled arm is kept instead");
        assert!(out.contains(", 2"));
    }

    #[test]
    fn keeps_the_compiled_arm_of_alternatives_with_no_comma_between() {
        let src = "\
static const int tbl[] = {
#ifdef UNDECLARED_FEATURE
    PAIR(1, 2)
#else
    PAIR(3, 4)
#endif
};
";
        let out = fixed(src);
        assert!(parses_clean(&out), "{out}");
        assert!(
            !out.contains("PAIR(1, 2)"),
            "the arm no build compiles is dropped"
        );
        assert!(out.contains("PAIR(3, 4)"));
    }

    #[test]
    fn leaves_undecidable_alternatives_with_no_comma_between_alone() {
        let src = "\
static const int tbl[] = {
#if FOO_VERSION >= 3
    1
#else
    2
#endif
};
";
        assert_eq!(blank_initializer_guarded_preproc(src), src);
    }

    #[test]
    fn keeps_every_arm_of_string_and_character_alternatives() {
        let src = "\
const char *names[] = {
#ifdef UNDECLARED_FEATURE
    \"a\", /* first */
#else
    \"b\",
#endif
};
const char chars[] = {
#ifdef UNDECLARED_FEATURE
    'a',
#else
    ',',
#endif
};
const char *words[] = {
#ifdef UNDECLARED_FEATURE
    \"\u{e9}t\u{e9}\",
#else
    \"hiver, // not a comment\",
#endif
};
";
        let out = fixed(src);
        assert!(parses_clean(&out), "{out}");
        for kept in ["\"a\",", "\"b\",", "'a',", "',',", "\"\u{e9}t\u{e9}\","] {
            assert!(out.contains(kept), "{kept} was dropped:\n{out}");
        }
    }

    #[test]
    fn literal_arms_with_no_comma_between_keep_one_arm() {
        let src = "\
char s[3] = {
#ifdef UNDECLARED_FEATURE
    \"ab\"
#else
    \"cd\"
#endif
};
";
        let out = fixed(src);
        assert!(parses_clean(&out), "{out}");
        assert!(
            !out.contains("\"ab\""),
            "the arm no build compiles is dropped"
        );
        assert!(out.contains("\"cd\""));
    }

    #[test]
    fn leaves_conditionals_outside_initializers_alone() {
        let src = "\
struct s {
#ifdef A
    int a;
#endif
    int b;
};
enum e {
#ifdef A
    E_A,
#endif
    E_B
};
int f(int x)
{
#ifdef A
    x++;
#endif
    return (int[]){
#ifdef A
        1,
#endif
        2 }[x];
}
";
        assert_eq!(blank_initializer_guarded_preproc(src), src);
    }

    #[test]
    fn leaves_a_conditional_inside_a_macro_argument_alone() {
        let src = "\
static const int tbl[] = {
    MK(1,
#ifdef A
       2,
#endif
       3),
    0
};
";
        assert_eq!(blank_initializer_guarded_preproc(src), src);
    }

    #[test]
    fn leaves_an_arm_holding_a_statement_alone() {
        let src = "\
static const int tbl[] = {
#ifdef A
    1 }; int y = {
#endif
    0
};
";
        assert_eq!(blank_initializer_guarded_preproc(src), src);
    }

    #[test]
    fn arms_opening_different_brace_counts_do_not_skew_the_scan() {
        let src = "\
#ifdef A
int g(int a) {
#else
int g(void) { int a = 0;
#endif
    return a;
}
int f(void)
{
#ifdef A
    g(1);
#endif
    return 0;
}
";
        assert_eq!(blank_initializer_guarded_preproc(src), src);
    }

    #[test]
    fn a_directive_inside_a_block_comment_is_not_one() {
        let src = "\
static const int tbl[] = {
/*
#ifdef A
*/
    1,
    0
};
";
        assert_eq!(blank_initializer_guarded_preproc(src), src);
    }

    #[test]
    fn a_crlf_file_is_blanked_at_the_bytes_of_its_lf_copy() {
        let src = "\
static const int tbl[] = {
#ifdef A
    1,
#endif
    0
};
";
        let lf = blank_initializer_guarded_preproc(src);
        assert_ne!(lf, src, "the LF copy must trigger the pass");
        let crlf = src.replace('\n', "\r\n");
        assert_eq!(
            blank_initializer_guarded_preproc(&crlf),
            lf.replace('\n', "\r\n")
        );
    }

    #[test]
    fn the_pass_scales_linearly_with_the_file() {
        let site = "\
static const int t[] = {
#ifdef A
    1,
#endif
    0
};
";
        let fastest = |sites: usize| {
            let src = site.repeat(sites);
            (0..3)
                .map(|_| {
                    let started = std::time::Instant::now();
                    std::hint::black_box(blank_initializer_guarded_preproc(&src));
                    started.elapsed()
                })
                .min()
                .unwrap()
        };
        let small = fastest(500);
        let large = fastest(4000);
        assert!(
            large < small * 24,
            "8x the input took {:.1}x as long ({small:?} -> {large:?})",
            large.as_secs_f64() / small.as_secs_f64()
        );
    }
}
