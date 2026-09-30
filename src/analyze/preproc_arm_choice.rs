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
//!   POSIX default, or the `--compile-commands` `-D`/`-U` state), and
//!   otherwise read as undefined, `0` -- the value C gives a name no
//!   configuration defines, and the build the project's opt-in (`WITH_*`)
//!   and opt-out (`NO_*`) options default to;
//! * a name the file itself `#define`s or `#undef`s, a function-like macro,
//!   arithmetic, or anything else the evaluator does not read makes the
//!   condition undecidable, and an undecidable conditional is not repaired
//!   at all: guessing would invent a configuration.
//!
//! [`dead_regions::platform_assumptions`]: crate::analyze::dead_regions::platform_assumptions

use crate::analyze::dead_regions;
use std::collections::HashSet;

/// The lines `line` and every `\`-continuation after it: one directive's
/// extent, as indices into `lines`.
pub(crate) fn directive_extent(lines: &[&str], line: usize) -> std::ops::Range<usize> {
    let mut last = line;
    while last + 1 < lines.len() && lines[last].trim_end().ends_with('\\') {
        last += 1;
    }
    line..last + 1
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
        Some(profile.get(name).copied().unwrap_or(false))
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
    };
    let v = p.or()?;
    (p.at == toks.len()).then_some(v)
}

struct Parser<'a> {
    toks: &'a [Tok],
    at: usize,
    defined: &'a dyn Fn(&str) -> Option<bool>,
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

    fn cmp(&mut self) -> Option<i64> {
        let l = self.unary()?;
        for op in ["==", "!=", "<=", ">=", "<", ">"] {
            if self.eat(op) {
                let r = self.unary()?;
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
                    false => Some(0),
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
        assert_eq!(
            arm("#if UNDEFINED_VERSION >= 3\na\n#else\nb\n#endif"),
            Some(1)
        );
    }

    #[test]
    fn the_scan_profile_decides_platform_names() {
        // POSIX default: `_WIN32` undefined, `__linux__` defined.
        assert_eq!(arm("#ifdef _WIN32\na\n#else\nb\n#endif"), Some(1));
        assert_eq!(arm("#if defined(__linux__)\na\n#else\nb\n#endif"), Some(0));
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
