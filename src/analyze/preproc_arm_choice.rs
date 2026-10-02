//! Which arm of a preprocessor conditional a build compiles, for the
//! pre-parse passes that keep ONE arm of a conditional tree-sitter cannot
//! parse with all of its arms in place (`paren_preproc_guard`, and
//! `preproc_split_chain` for arms that each open the shared body).
//!
//! Keeping an arm decides which code the rules see, and so which findings
//! exist for that stretch of source -- in tension with ADR-0010 Decision 3,
//! under which a profile never decides emission. It is accepted only as the
//! cost of a parse repair, where the alternative is losing the enclosing
//! function (or file) to every rule, and it is made the way the scan's
//! profile says the build is configured rather than by position:
//!
//! * each arm's condition is evaluated in order and the first true one is
//!   kept (`#else` is true);
//! * a name is resolved through [`dead_regions::platform_assumptions`] (the
//!   POSIX default, or the `--compile-commands` `-D`/`-U` state);
//! * a project name the profile does not declare, tested for definedness
//!   (`#ifdef WITH_X`, `defined(NO_Y)`, a bare `#if WITH_X`), is read as
//!   undefined, `0`. That is the configuration with those macros undefined
//!   -- the no-build-system convention -- NOT necessarily the project's
//!   default build: mosquitto's build turns `WITH_TLS`, `WITH_BRIDGE`,
//!   `WITH_UNIX_SOCKETS` and `WITH_BROKER` on, so with no profile declared
//!   its repaired sites keep the arm those options switch off;
//! * everything else makes the condition undecidable, and an undecidable
//!   conditional is not repaired at all, because guessing would invent a
//!   configuration: a name the file itself `#define`s or `#undef`s; a
//!   compiler-reserved name the profile does not declare (`__GNUC__`,
//!   `__STDC_VERSION__`, `__APPLE__`), which only the implementation knows;
//!   a comparison any operand of which reads a name as undefined
//!   (`#if FOO_VERSION >= 3`, `#if (1 && FOO) > 0`), since a name compared
//!   with a value is a value macro some header almost certainly defines; a
//!   function-like macro; arithmetic; anything else the evaluator does not
//!   read.
//!
//! [`dead_regions::platform_assumptions`]: crate::analyze::dead_regions::platform_assumptions

use crate::analyze::dead_regions;
use std::collections::HashSet;

/// The lines `line` and every `\`-continuation after it: one directive's
/// extent, as indices into `lines`.
///
/// A block comment the directive opens and does not close is part of it too
/// (`#if !defined(A) /* ...` on one line, `... */` on the next): left out,
/// the comment's closing text would land in the arm after it as code. So is
/// anything after that `*/` on its line: comments become a space before
/// directives are read (C11 5.1.1.2, phases 3-4), so that text is the
/// directive's -- read into an `#if`'s condition, and dropped as extra
/// tokens after `#else` or `#endif`, as a compiler drops it.
pub(crate) fn directive_extent(lines: &[&str], line: usize) -> std::ops::Range<usize> {
    let mut last = line;
    let mut in_comment = false;
    loop {
        in_comment = ends_in_block_comment(lines[last], in_comment);
        let continued = lines[last].trim_end().ends_with('\\');
        if (!continued && !in_comment) || last + 1 >= lines.len() {
            break;
        }
        last += 1;
    }
    line..last + 1
}

/// Whether a `/*` comment is still open at the end of `line`, given whether
/// one was open at its start. String and character literals are skipped.
fn ends_in_block_comment(line: &str, mut in_comment: bool) -> bool {
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if in_comment {
            if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                in_comment = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'*') => {
                in_comment = true;
                i += 2;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => return false,
            q @ (b'"' | b'\'') => {
                i += 1;
                while i < b.len() && b[i] != q {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    in_comment
}

/// The text of the directive starting at `line`, continuations joined.
fn directive_text(lines: &[&str], line: usize) -> String {
    directive_extent(lines, line)
        .map(|k| lines[k].trim_end().trim_end_matches('\\'))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Names the file `#define`s or `#undef`s anywhere: their state at a given
/// line depends on what came before it, which this module does not track.
pub(crate) fn locally_defined_names(lines: &[&str]) -> HashSet<String> {
    lines
        .iter()
        .filter_map(|l| {
            let rest = l.trim_start().strip_prefix('#')?.trim_start();
            let rest = rest
                .strip_prefix("define")
                .or_else(|| rest.strip_prefix("undef"))?;
            if !rest.starts_with(char::is_whitespace) {
                return None;
            }
            let name: String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

/// The index of the arm a build compiles, given the lines that open each
/// arm (`#if`/`#ifdef`/`#ifndef`, then each `#elif`/`#else`) in order.
/// `None` when a condition cannot be decided, or when no arm compiles (an
/// `#if`/`#elif` chain with no `#else`, every condition false).
pub(crate) fn compiled_arm(
    lines: &[&str],
    openers: &[usize],
    local: &HashSet<String>,
) -> Option<usize> {
    let profile = dead_regions::platform_assumptions();
    let defined = |name: &str| -> Option<bool> {
        if local.contains(name) {
            return None;
        }
        match profile.get(name) {
            Some(&declared) => Some(declared),
            None if is_reserved(name) => None,
            None => Some(false),
        }
    };
    for (arm, &line) in openers.iter().enumerate() {
        let text = strip_comments(&directive_text(lines, line));
        let rest = text.trim_start().strip_prefix('#')?.trim_start();
        let keyword: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let condition = rest[keyword.len()..].trim();
        let value = match keyword.as_str() {
            "else" => true,
            "ifdef" => defined(first_word(condition)?)?,
            "ifndef" => !defined(first_word(condition)?)?,
            "if" | "elif" => evaluate(condition, &defined)? != 0,
            _ => return None,
        };
        if value {
            return Some(arm);
        }
    }
    None
}

/// An identifier reserved to the implementation (C11 7.1.3): `__x`, or `_`
/// and an uppercase letter. The compiler defines these, so an undeclared one
/// is unknown, never "undefined".
fn is_reserved(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next() == Some('_')
        && chars
            .next()
            .is_some_and(|c| c == '_' || c.is_ascii_uppercase())
}

fn first_word(s: &str) -> Option<&str> {
    let end = s
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    (end > 0).then(|| &s[..end])
}

/// `s` with `/* */` and `//` comments removed.
fn strip_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    loop {
        let block = rest.find("/*");
        let line = rest.find("//");
        match (block, line) {
            (Some(b), l) if l.is_none_or(|l| b < l) => {
                out.push_str(&rest[..b]);
                out.push(' ');
                match rest[b + 2..].find("*/") {
                    Some(e) => rest = &rest[b + 2 + e + 2..],
                    None => return out,
                }
            }
            (_, Some(l)) => {
                out.push_str(&rest[..l]);
                return out;
            }
            _ => {
                out.push_str(rest);
                return out;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(i64),
    Name(String),
    Op(&'static str),
}

fn tokenize(s: &str) -> Option<Vec<Tok>> {
    const OPS: &[&str] = &["&&", "||", "==", "!=", "<=", ">=", "!", "<", ">", "(", ")"];
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i] as char;
        if c.is_whitespace() {
            i += 1;
        } else if c.is_ascii_digit() {
            let start = i;
            while i < b.len() && (b[i] as char).is_ascii_alphanumeric() {
                i += 1;
            }
            let lit = s[start..i].trim_end_matches(['u', 'U', 'l', 'L']);
            let n = if let Some(hex) = lit.strip_prefix("0x").or_else(|| lit.strip_prefix("0X")) {
                i64::from_str_radix(hex, 16).ok()?
            } else {
                lit.parse().ok()?
            };
            out.push(Tok::Num(n));
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < b.len() && ((b[i] as char).is_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push(Tok::Name(s[start..i].to_string()));
        } else {
            let op = OPS.iter().find(|op| s[i..].starts_with(**op))?;
            out.push(Tok::Op(op));
            i += op.len();
        }
    }
    Some(out)
}

/// A `#if` condition's value, or `None` when it holds anything this reader
/// does not decide.
fn evaluate(condition: &str, defined: &dyn Fn(&str) -> Option<bool>) -> Option<i64> {
    let toks = tokenize(condition)?;
    let mut p = Parser {
        toks: &toks,
        at: 0,
        defined,
        guessed: false,
    };
    let v = p.or()?;
    (p.at == toks.len()).then_some(v)
}

struct Parser<'a> {
    toks: &'a [Tok],
    at: usize,
    defined: &'a dyn Fn(&str) -> Option<bool>,
    /// Set when an operand's value came from reading an undeclared name as
    /// undefined, `0` -- a guess a comparison must not decide on.
    guessed: bool,
}

impl Parser<'_> {
    fn eat(&mut self, op: &str) -> bool {
        if matches!(self.toks.get(self.at), Some(Tok::Op(o)) if *o == op) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn or(&mut self) -> Option<i64> {
        let mut v = self.and()?;
        while self.eat("||") {
            let r = self.and()?;
            v = i64::from(v != 0 || r != 0);
        }
        Some(v)
    }

    fn and(&mut self) -> Option<i64> {
        let mut v = self.cmp()?;
        while self.eat("&&") {
            let r = self.cmp()?;
            v = i64::from(v != 0 && r != 0);
        }
        Some(v)
    }

    /// A comparison, or the operand alone. `guessed` is left set if it was
    /// on entry or any operand set it, so a guess inside a parenthesised
    /// operand (`(1 && FOO) > 0`) reaches every comparison enclosing it.
    fn cmp(&mut self) -> Option<i64> {
        let outer = std::mem::take(&mut self.guessed);
        let l = self.unary()?;
        let l_guessed = std::mem::take(&mut self.guessed);
        for op in ["==", "!=", "<=", ">=", "<", ">"] {
            if self.eat(op) {
                let r = self.unary()?;
                // `FOO >= 3` compares a value macro, which some header
                // defines: its value is not the `0` of an undefined name.
                if l_guessed || self.guessed {
                    return None;
                }
                self.guessed = outer;
                return Some(i64::from(match op {
                    "==" => l == r,
                    "!=" => l != r,
                    "<=" => l <= r,
                    ">=" => l >= r,
                    "<" => l < r,
                    _ => l > r,
                }));
            }
        }
        self.guessed = outer || l_guessed;
        Some(l)
    }

    fn unary(&mut self) -> Option<i64> {
        if self.eat("!") {
            return Some(i64::from(self.unary()? == 0));
        }
        if self.eat("(") {
            let v = self.or()?;
            return self.eat(")").then_some(v);
        }
        match self.toks.get(self.at)?.clone() {
            Tok::Num(n) => {
                self.at += 1;
                Some(n)
            }
            Tok::Name(name) if name == "defined" => {
                self.at += 1;
                let paren = self.eat("(");
                let Tok::Name(target) = self.toks.get(self.at)?.clone() else {
                    return None;
                };
                self.at += 1;
                if paren && !self.eat(")") {
                    return None;
                }
                Some(i64::from((self.defined)(&target)?))
            }
            Tok::Name(name) => {
                self.at += 1;
                // A macro invocation's value is unknown.
                if self.toks.get(self.at) == Some(&Tok::Op("(")) {
                    return None;
                }
                // Defined with a value nothing here knows, or undefined: 0.
                match (self.defined)(&name)? {
                    true => None,
                    false => {
                        self.guessed = true;
                        Some(0)
                    }
                }
            }
            Tok::Op(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arm(src: &str) -> Option<usize> {
        let lines: Vec<&str> = src.lines().collect();
        let openers: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| {
                let t = l.trim_start();
                t.starts_with('#') && !t.contains("endif")
            })
            .map(|(i, _)| i)
            .collect();
        compiled_arm(&lines, &openers, &locally_defined_names(&lines))
    }

    #[test]
    fn an_undefined_option_selects_its_default_arm() {
        assert_eq!(arm("#ifndef NO_GETOPT_LONG\na\n#else\nb\n#endif"), Some(0));
        assert_eq!(arm("#ifdef WITH_LDAP\na\n#else\nb\n#endif"), Some(1));
        assert_eq!(
            arm("#if defined(WITH_LDAP) || defined(WITH_MYSQL)\na\n#else\nb\n#endif"),
            Some(1)
        );
        assert_eq!(
            arm("#if !defined(A) || defined(B)\na\n#else\nb\n#endif"),
            Some(0)
        );
        assert_eq!(arm("#if !(defined(A))\na\n#else\nb\n#endif"), Some(0));
        assert_eq!(
            arm("#if !defined(A) /* why */\na\n#else\nb\n#endif"),
            Some(0)
        );
    }

    #[test]
    fn elif_conditions_are_read() {
        assert_eq!(
            arm("#ifdef A\na\n#elif !defined(B)\nb\n#else\nc\n#endif"),
            Some(1)
        );
    }

    #[test]
    fn literal_conditions_are_read() {
        assert_eq!(arm("#if 1\na\n#else\nb\n#endif"), Some(0));
        assert_eq!(arm("#if 0\na\n#else\nb\n#endif"), Some(1));
        // An undeclared name compared with a value is a value macro some
        // header defines, not an undefined one.
        assert_eq!(arm("#if UNDEFINED_VERSION >= 3\na\n#else\nb\n#endif"), None);
        assert_eq!(
            arm("#if FOO > 2 || defined(BAR)\na\n#else\nb\n#endif"),
            None
        );
    }

    #[test]
    fn the_scan_profile_decides_platform_names() {
        // POSIX default: `_WIN32` undefined, `__linux__` defined.
        assert_eq!(arm("#ifdef _WIN32\na\n#else\nb\n#endif"), Some(1));
        assert_eq!(arm("#if defined(__linux__)\na\n#else\nb\n#endif"), Some(0));
    }

    #[test]
    fn compiler_reserved_names_are_unknown_unless_declared() {
        assert_eq!(arm("#if __GNUC__ >= 4\na\n#else\nb\n#endif"), None);
        assert_eq!(arm("#ifdef __GNUC__\na\n#else\nb\n#endif"), None);
        assert_eq!(
            arm("#if __STDC_VERSION__ >= 199901L\na\n#else\nb\n#endif"),
            None
        );
        assert_eq!(
            arm("#if defined(_FORTIFY_SOURCE)\na\n#else\nb\n#endif"),
            None
        );
        // The profile declares these.
        assert_eq!(arm("#ifdef _MSC_VER\na\n#else\nb\n#endif"), Some(1));
        assert_eq!(arm("#if defined(__linux__)\na\n#else\nb\n#endif"), Some(0));
    }

    #[test]
    fn a_block_comment_the_directive_leaves_open_is_part_of_it() {
        let src = "#if !defined(A) /* start\n   end */\n    a\n#else\n    b\n#endif";
        let lines: Vec<&str> = src.lines().collect();
        assert_eq!(directive_extent(&lines, 0), 0..2);
        assert_eq!(compiled_arm(&lines, &[0, 3], &HashSet::new()), Some(0));
        let closed = ["#if A /* c */", "x"];
        assert_eq!(directive_extent(&closed, 0), 0..1);
    }

    #[test]
    fn text_after_the_comment_a_directive_left_open_is_the_directive_s() {
        // The comment is one space, so `&& 0` is part of the condition.
        let src = "#if 1 /* c\n */ && 0\n    a\n#else\n    b\n#endif";
        let lines: Vec<&str> = src.lines().collect();
        assert_eq!(directive_extent(&lines, 0), 0..2);
        assert_eq!(compiled_arm(&lines, &[0, 3], &HashSet::new()), Some(1));
        // After `#else` it is extra tokens a compiler ignores: still the
        // directive's, not the arm's.
        let lines = ["#ifdef A", "    0", "#else /* c", "   */ g(u)", "#endif"];
        assert_eq!(directive_extent(&lines, 2), 2..4);
        assert_eq!(compiled_arm(&lines, &[0, 2], &HashSet::new()), Some(1));
    }

    #[test]
    fn a_guess_anywhere_in_a_comparison_leaves_it_undecided() {
        assert_eq!(arm("#if (1 && FOO) > 0\na\n#else\nb\n#endif"), None);
        assert_eq!(arm("#if (FOO && 1) > 0\na\n#else\nb\n#endif"), None);
        assert_eq!(arm("#if 0 < (1 && !FOO)\na\n#else\nb\n#endif"), None);
        assert_eq!(arm("#if ((FOO)) == 0\na\n#else\nb\n#endif"), None);
        // A guess outside the comparison does not reach it, and a bare
        // definedness test still reads the name as undefined.
        assert_eq!(arm("#if FOO || 1 > 0\na\n#else\nb\n#endif"), Some(0));
        assert_eq!(
            arm("#if (FOO && 1) || defined(B)\na\n#else\nb\n#endif"),
            Some(1)
        );
        assert_eq!(arm("#if defined(A) == 0\na\n#else\nb\n#endif"), Some(0));
    }

    #[test]
    fn what_cannot_be_decided_selects_nothing() {
        // A name the file defines itself, a macro call, a name the profile
        // knows as defined but whose value is unknown.
        assert_eq!(arm("#define A 1\n#if A\na\n#else\nb\n#endif"), None);
        assert_eq!(arm("#if VERSION_AT_LEAST(3)\na\n#else\nb\n#endif"), None);
        assert_eq!(arm("#if __linux__ > 2\na\n#else\nb\n#endif"), None);
        assert_eq!(arm("#if A + 1\na\n#else\nb\n#endif"), None);
        // No arm compiles.
        assert_eq!(arm("#ifdef A\na\n#elif defined(B)\nb\n#endif"), None);
    }

    #[test]
    fn a_continued_condition_is_read_whole() {
        let src = "#if defined(A) || \\\n    !defined(B)\na\n#else\nb\n#endif";
        let lines: Vec<&str> = src.lines().collect();
        assert_eq!(directive_extent(&lines, 0), 0..2);
        assert_eq!(compiled_arm(&lines, &[0, 3], &HashSet::new()), Some(0));
    }
}
