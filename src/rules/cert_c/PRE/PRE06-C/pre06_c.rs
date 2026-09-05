// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use tree_sitter::Node;

pub struct Pre06C;

impl CertRule for Pre06C {
    fn rule_id(&self) -> &'static str {
        "PRE06-C"
    }
    fn description(&self) -> &'static str {
        "Enclose header files in an include guard"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }
    fn cert_id(&self) -> &'static str {
        "PRE06-C"
    }

    fn applies_to_file(&self, file_path: &str) -> bool {
        matches!(
            std::path::Path::new(file_path)
                .extension()
                .and_then(|e| e.to_str()),
            Some("h" | "hpp" | "hh" | "hxx")
        )
    }

    fn check(&self, _node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // A real include guard must *enclose the whole file*: its #ifndef
        // has to be the first significant line and its #endif the last.
        // Just checking that a matching #ifndef/#define pair exists
        // *somewhere* also passes headers with no real guard at all that
        // merely contain an unrelated ifndef/define idiom later on (e.g.
        // a "default this constant if the build didn't override it" block).
        //
        // The C preprocessor allows whitespace between `#` and the
        // directive name (`#  define X`, common in indented nested
        // conditionals in this codebase), so `directive` strips that gap
        // explicitly rather than relying on a literal "#define" prefix.
        // Returns the (possibly empty) remainder after the directive name —
        // `#endif` legitimately has no argument, so an empty remainder
        // must still count as a match, not as "directive didn't match".
        fn directive<'a>(line: &'a str, name: &str) -> Option<&'a str> {
            let rest = line
                .trim_start()
                .strip_prefix('#')?
                .trim_start()
                .strip_prefix(name)?;
            (rest.is_empty() || rest.starts_with(char::is_whitespace)).then(|| rest.trim())
        }
        fn directive_arg<'a>(line: &'a str, name: &str) -> Option<&'a str> {
            directive(line, name)?.split_whitespace().next()
        }

        // Blank out block (/* */) and line (//) comments, preserving
        // newlines, so comment text can't be mistaken for a directive and
        // a license-header comment block doesn't hide the true first line.
        fn strip_comments(source: &str) -> String {
            let bytes = source.as_bytes();
            let mut out = String::with_capacity(source.len());
            let (mut in_block, mut in_line) = (false, false);
            let mut i = 0;
            while i < bytes.len() {
                let c = bytes[i] as char;
                if in_block {
                    if c == '*' && bytes.get(i + 1) == Some(&b'/') {
                        in_block = false;
                        out.push_str("  ");
                        i += 2;
                    } else {
                        out.push(if c == '\n' { '\n' } else { ' ' });
                        i += 1;
                    }
                } else if in_line {
                    if c == '\n' {
                        in_line = false;
                        out.push('\n');
                    } else {
                        out.push(' ');
                    }
                    i += 1;
                } else if c == '/' && bytes.get(i + 1) == Some(&b'*') {
                    in_block = true;
                    out.push_str("  ");
                    i += 2;
                } else if c == '/' && bytes.get(i + 1) == Some(&b'/') {
                    in_line = true;
                    out.push_str("  ");
                    i += 2;
                } else {
                    out.push(c);
                    i += 1;
                }
            }
            out
        }

        // Some guards use the equivalent `#if !defined(NAME)` form instead
        // of `#ifndef NAME` (seen in real headers, e.g. sqlite3expert.h);
        // search anywhere in the condition so a compound guard like
        // `#if defined(_WIN32) && !defined(NAME)` is still recognized.
        fn negated_guard_name(cond: &str) -> Option<&str> {
            let idx = cond.find("!defined")?;
            let after = cond[idx + "!defined".len()..]
                .trim_start()
                .strip_prefix('(')?;
            let end = after.find(')')?;
            Some(after[..end].trim())
        }

        let stripped = strip_comments(source);
        let significant: Vec<&str> = stripped
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();

        // A real guard must *enclose the whole file*: nesting depth (from
        // #ifndef/#if/#ifdef pushing and #endif popping) must not return to
        // zero until the very last significant line. Without this, a file
        // made of many short back-to-back `#ifndef X / #define X / #endif`
        // "default this constant" blocks (unrelated to a header guard) can
        // look like a guard just because its first opener and last closer
        // happen to be an #ifndef and an #endif.
        let mut guard_name: Option<&str> = None;
        let mut depth: i32 = 0;
        let mut closed_early = false;
        for (idx, line) in significant.iter().enumerate() {
            let opens = directive_arg(line, "ifndef").is_some()
                || directive(line, "ifdef").is_some()
                || directive(line, "if").is_some();
            if opens {
                if idx == 0 {
                    guard_name = directive_arg(line, "ifndef")
                        .or_else(|| directive(line, "if").and_then(negated_guard_name));
                    if guard_name.is_none() {
                        break;
                    }
                }
                depth += 1;
            } else if directive(line, "endif").is_some() {
                depth -= 1;
                if depth == 0 && idx != significant.len() - 1 {
                    closed_early = true;
                }
            }
        }
        let encloses_file = guard_name.is_some() && !closed_early && depth == 0;

        // The #define is expected to follow shortly after the #ifndef —
        // scan a small window rather than requiring the very next line, to
        // tolerate a comment or blank line in between.
        let guard_defined = guard_name.is_some_and(|name| {
            significant
                .iter()
                .skip(1)
                .take(5)
                .any(|line| directive_arg(line, "define") == Some(name))
        });

        if guard_name.is_none() || !guard_defined || !encloses_file {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                line: 1,
                column: 1,
                file_path: String::new(),
                message: "Header file missing include guard".to_string(),
                suggestion: Some(
                    "Add #ifndef HEADER_H / #define HEADER_H / #endif guard".to_string(),
                ),
                requires_manual_review: None,
            });
        }

        violations
    }
}
