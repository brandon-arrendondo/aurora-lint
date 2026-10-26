//! A test fixture's header: the `Expect:` and `Settings:` lines of its
//! leading comment, and the `Expect: here` markers trailing its code.
//!
//! This file is compiled twice: by `build.rs`, which generates a test per
//! fixture and preset from what it reads here, and, under `cfg(test)`, into
//! the library (`src/lib.rs`) so the grammar has unit tests. It therefore
//! uses only `std` and `anyhow`.

use anyhow::{Context, Result};
use std::fs;

/// The presets every fixture runs under. With [`OPT_IN_PRESETS`], must match
/// `settings::Preset`.
pub const PRESETS: &[&str] = &["default", "strict"];

/// The presets a fixture runs under only when its `Expect:` line names them.
/// The preset matrix covers only the rules whose verdict a preset changes
/// (ADR-0015, 2026-10-07 amendment, Decision 5), so a fixture whose header
/// does not name `pedantic` is not run under it.
pub const OPT_IN_PRESETS: &[&str] = &["pedantic"];

/// What a fixture's leading comment says about settings.
pub struct FixtureHeader {
    /// `Expect: default=clean strict=violation` -- per-preset expectations
    /// that override the directory's.
    pub expect: Vec<(String, String)>,
    /// `Settings: name=value, name=value` -- option overrides applied on top
    /// of each preset.
    pub settings: String,
    /// The 1-indexed lines a trailing `/* Expect: here */` (or
    /// `// Expect: here`) marks: a run that expects a violation must report
    /// one on each.
    pub expected_lines: Vec<usize>,
    /// `Expect: count=N` -- a run that expects a violation must report
    /// exactly N findings, not merely one.
    pub count: Option<usize>,
}

/// Read a fixture's `Expect:` and `Settings:` lines from its leading comment
/// (everything before the first line of code). The grammar is strict so a
/// directive can never be silently ignored:
/// - a trailing `*/` is dropped, so `/* Expect: ... */` on one line works;
/// - a second `Expect:` or `Settings:` line is an error;
/// - a directive spelled in another case (`expect:`, `SETTINGS:`) is an error;
/// - a comment line carrying a directive after the first line of code is an
///   error (code such as `printf("Settings: ...")` is not a comment line and
///   is ignored).
///
/// The one directive allowed after the leading comment is the line marker
/// `Expect: here`, in a comment trailing the code it marks. Any comment
/// that opens with `expect:`, in any case and spacing, is taken for a
/// marker, so a near-miss fails the build instead of marking nothing: the
/// marker must be spelled `/* Expect: here */` or `// Expect: here`, close
/// on the line it marks, and stand on a line with code.
pub fn fixture_header(path: &std::path::Path) -> Result<FixtureHeader> {
    let source = fs::read_to_string(path).with_context(|| format!("read {:?}", path))?;
    fixture_header_of(&source)
}

/// [`fixture_header`] on a fixture's text. Errors name the line; the caller
/// names the fixture.
pub fn fixture_header_of(source: &str) -> Result<FixtureHeader> {
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let mut header = FixtureHeader {
        expect: Vec::new(),
        settings: String::new(),
        expected_lines: Vec::new(),
        count: None,
    };
    let (mut saw_expect, mut saw_settings, mut in_code) = (false, false, false);
    let mut in_block = false;
    for (lineno, line) in source.lines().enumerate() {
        let at = format!("line {}", lineno + 1);
        let parts = split_fixture_line(line, &mut in_block);
        let markers = parts.comments.iter().filter(|c| opens_with_expect(c.text));
        if parts.has_code {
            in_code = true;
            for comment in markers {
                check_marker(comment).with_context(|| at.clone())?;
                header.expected_lines.push(lineno + 1);
            }
            continue;
        }
        for comment in markers {
            let value = comment
                .text
                .trim_start_matches(|c: char| c == '*' || c.is_whitespace());
            anyhow::ensure!(
                !value[EXPECT.len()..].trim().eq_ignore_ascii_case("here"),
                "{}: `Expect: here` must trail the code it marks, in a comment that opens and closes on that line",
                at
            );
        }
        let l = line
            .trim()
            .trim_start_matches(|c: char| c == '*' || c == '/' || c.is_whitespace());
        let l = l.strip_suffix("*/").map_or(l, str::trim_end);
        let directive = ["Expect:", "Settings:"].into_iter().find(|d| {
            l.get(..d.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(d))
        });
        let Some(directive) = directive else {
            continue;
        };
        anyhow::ensure!(
            l.starts_with(directive),
            "{}: fixture directive must be spelled `{}`",
            at,
            directive
        );
        anyhow::ensure!(
            !in_code,
            "{}: `{}` must be in the fixture's leading comment, before any code",
            at,
            directive
        );
        let rest = &l[directive.len()..];
        if directive == "Expect:" {
            anyhow::ensure!(!saw_expect, "{}: a second `Expect:` line", at);
            saw_expect = true;
            for pair in rest.split_whitespace() {
                let (preset, outcome) = pair
                    .split_once('=')
                    .with_context(|| format!("{}: bad Expect entry '{}'", at, pair))?;
                if preset == "count" {
                    anyhow::ensure!(header.count.is_none(), "{}: a second `count=`", at);
                    let n: usize = outcome.parse().with_context(|| {
                        format!("{}: Expect count must be a number, got '{}'", at, outcome)
                    })?;
                    anyhow::ensure!(n > 0, "{}: `count=0` is a clean fixture: say clean", at);
                    header.count = Some(n);
                    continue;
                }
                anyhow::ensure!(
                    PRESETS.contains(&preset) || OPT_IN_PRESETS.contains(&preset),
                    "{}: Expect names unknown preset '{}'",
                    at,
                    preset
                );
                let outcome = match outcome {
                    "clean" => "Clean",
                    "violation" => "Violation",
                    _ => anyhow::bail!(
                        "{}: Expect outcome must be clean or violation, got '{}'",
                        at,
                        outcome
                    ),
                };
                header
                    .expect
                    .push((preset.to_string(), outcome.to_string()));
            }
        } else {
            anyhow::ensure!(!saw_settings, "{}: a second `Settings:` line", at);
            saw_settings = true;
            header.settings = rest.trim().to_string();
        }
    }
    Ok(header)
}

const EXPECT: &str = "expect:";

/// One line of a fixture, split into code and comments.
struct FixtureLine<'a> {
    /// Whether the line holds anything but comments and whitespace. A
    /// string or character literal is code, and a comment opener inside one
    /// opens nothing.
    has_code: bool,
    comments: Vec<FixtureComment<'a>>,
}

/// One comment, or the part of a block comment, on a fixture line.
struct FixtureComment<'a> {
    /// `/*` or `//`, or `None` for a block comment opened on an earlier line.
    opener: Option<&'static str>,
    /// The text between the opener (or the line's start) and the closer (or
    /// the line's end).
    text: &'a str,
    /// Whether the comment ends on this line (a `//` comment always does).
    closed: bool,
}

/// Split `line` into code and comments; `in_block` says whether the line
/// starts inside a block comment, and is left saying whether it ends in one.
fn split_fixture_line<'a>(line: &'a str, in_block: &mut bool) -> FixtureLine<'a> {
    let b = line.as_bytes();
    let mut parts = FixtureLine {
        has_code: false,
        comments: Vec::new(),
    };
    let (mut i, mut start, mut opener) = (0, 0, None);
    loop {
        if *in_block {
            let Some(end) = line[i..].find("*/") else {
                parts.comments.push(FixtureComment {
                    opener,
                    text: &line[start..],
                    closed: false,
                });
                return parts;
            };
            parts.comments.push(FixtureComment {
                opener,
                text: &line[start..i + end],
                closed: true,
            });
            i += end + 2;
            *in_block = false;
            continue;
        }
        let Some(&c) = b.get(i) else {
            return parts;
        };
        match (c, b.get(i + 1)) {
            (b'/', Some(b'*')) => {
                *in_block = true;
                opener = Some("/*");
                i += 2;
                start = i;
            }
            (b'/', Some(b'/')) => {
                parts.comments.push(FixtureComment {
                    opener: Some("//"),
                    text: &line[i + 2..],
                    closed: true,
                });
                return parts;
            }
            (b'"' | b'\'', _) => {
                parts.has_code = true;
                i += 1;
                while i < b.len() && b[i] != c {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                i = (i + 1).min(b.len());
            }
            _ => {
                parts.has_code |= !c.is_ascii_whitespace();
                i += 1;
            }
        }
    }
}

/// Whether a comment opens with `expect:`, in any case, after any
/// whitespace (and, in a block comment, any `*`).
fn opens_with_expect(text: &str) -> bool {
    text.trim_start_matches(|c: char| c == '*' || c.is_whitespace())
        .get(..EXPECT.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(EXPECT))
}

/// Check a comment that opens with `expect:` and trails code: it must be
/// the line marker, spelled exactly and closed on this line.
fn check_marker(comment: &FixtureComment) -> Result<()> {
    let spelled = match comment.opener {
        Some(_) if comment.closed => comment.text.strip_prefix(" Expect:"),
        _ => None,
    };
    let Some(value) = spelled else {
        anyhow::bail!(
            "write the line marker as `/* Expect: here */` or `// Expect: here`, \
             closed on the line it marks; got `{}{}{}`",
            comment.opener.unwrap_or(""),
            comment.text,
            if comment.opener == Some("/*") && comment.closed {
                "*/"
            } else {
                ""
            }
        );
    };
    anyhow::ensure!(
        value.trim() == "here",
        "only `Expect: here` may trail code, got `Expect: {}`",
        value.trim()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::fixture_header_of;

    const HEAD: &str = "/*\n * Expect: count=1\n */\n";

    fn marked_lines(body: &str) -> Vec<usize> {
        fixture_header_of(&format!("{HEAD}{body}"))
            .unwrap_or_else(|e| panic!("{body:?} should parse: {e:#}"))
            .expected_lines
    }

    fn error(body: &str) -> String {
        match fixture_header_of(&format!("{HEAD}{body}")) {
            Ok(_) => panic!("{body:?} should fail the build"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn the_two_spellings_mark_their_line() {
        assert_eq!(marked_lines("int x; /* Expect: here */\n"), [4]);
        assert_eq!(marked_lines("int x; // Expect: here\n"), [4]);
        assert_eq!(
            marked_lines("#define M(a) \\\n  f(a) /* Expect: here */ \\\n  + 1\n"),
            [5]
        );
    }

    #[test]
    fn near_misses_fail_the_build() {
        for body in [
            "int x; /*Expect: here*/\n",
            "int x; /*  Expect: here */\n",
            "int x; /*\tExpect: here */\n",
            "int x; //Expect: here\n",
            "int x; // expect: here\n",
            "int x; /* EXPECT: here */\n",
            "int x; /* Expect: here\n */\n",
        ] {
            assert!(
                error(body).contains("write the line marker as"),
                "{body:?}: {}",
                error(body)
            );
        }
    }

    #[test]
    fn a_marker_on_its_own_line_fails_the_build() {
        for body in [
            "int x; /*\n   Expect: here */\n",
            "int x;\n/* Expect: here */\n",
            "int x;\n// expect: HERE\n",
        ] {
            assert!(
                error(body).contains("must trail the code it marks"),
                "{body:?}: {}",
                error(body)
            );
        }
    }

    #[test]
    fn only_here_may_trail_code() {
        assert!(error("int x; /* Expect: there */\n").contains("only `Expect: here`"));
    }

    #[test]
    fn literals_and_other_comments_are_not_markers() {
        assert!(marked_lines("char *s = \"/* Expect: here */\";\n").is_empty());
        assert!(marked_lines("char c = '\"'; /* we expect a finding */\n").is_empty());
        // An opener inside a string opens nothing, so a later line is code.
        assert_eq!(
            marked_lines("char *p = \"/tmp/*.c\";\nint x; /* Expect: here */\n"),
            [5]
        );
    }

    #[test]
    fn header_lines_without_a_leading_star_are_read() {
        let h = fixture_header_of("/*\n  Expect: default=clean\n  Settings: a=1\n*/\nint x;\n")
            .unwrap();
        assert_eq!(h.expect, [("default".to_string(), "Clean".to_string())]);
        assert_eq!(h.settings, "a=1");
    }

    #[test]
    fn a_byte_order_mark_does_not_hide_the_header() {
        let h = fixture_header_of("\u{feff}/* Expect: count=2 */\nint x; /* Expect: here */\n")
            .unwrap();
        assert_eq!((h.count, h.expected_lines), (Some(2), vec![2]));
    }

    #[test]
    fn count_must_be_a_positive_number() {
        assert!(fixture_header_of("/* Expect: count=0 */\n").is_err());
        assert!(fixture_header_of("/* Expect: count=two */\n").is_err());
        assert!(fixture_header_of("/* Expect: count=1 count=2 */\n").is_err());
    }
}
