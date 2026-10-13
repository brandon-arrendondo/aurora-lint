// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! Pre-parse pass: spell the C11 keyword `_Thread_local` as `thread_local`.
//!
//! tree-sitter-c's grammar lists `thread_local` (C23, and the `<threads.h>`
//! macro) and GNU's `__thread` as storage-class specifiers, but not
//! `_Thread_local`. It reads `_Thread_local int x;` as a declaration of
//! type `_Thread_local` whose declarator is `int`, and strands `x` in an
//! `ERROR` node, so no rule can resolve the object or see its type. The two
//! spellings mean the same thing, so each `_Thread_local` token outside a
//! comment or literal becomes `thread_local` followed by a space: the same
//! byte length and lines, so every position downstream is unchanged, and a
//! `storage_class_specifier` node every rule already reads.
//!
//! A directive's spelling is left alone where it names something rather
//! than declares an object: the header an `#include`, `#include_next` or
//! `#import` names, every `#if`/`#ifdef`/`#ifndef`/`#elif` condition
//! (`defined(_Thread_local)` asks about that macro), and the name a
//! `#define` defines, along with the whole definition of a `thread_local`
//! macro (`#define thread_local _Thread_local` must not expand to itself).
//!
//! The respelling is the parser's alone. Suppression hashes read the file's
//! own text, and [`restore_spelling`] puts `_Thread_local` back into a
//! message that quotes a respelled line.

use crate::utility::cert_c::pp_tokens::parse_define_directive;
use crate::utility::cert_c::pp_tokens::{directive_end, directive_starts, mask_source};
use std::borrow::Cow;
use std::ops::Range;

const KEYWORD: &str = "_Thread_local";
const SPELLING: &str = "thread_local ";

/// `source` with every `_Thread_local` token spelled `thread_local `.
pub fn spell_thread_local(source: &str) -> Cow<'_, str> {
    if !source.contains(KEYWORD) {
        return Cow::Borrowed(source);
    }
    let masked = mask_source(source);
    let kept = kept_ranges(source);
    let is_ident = |b: u8| b == b'_' || b.is_ascii_alphanumeric();
    let mut out = source.as_bytes().to_vec();
    let mut changed = false;
    for (at, _) in masked.match_indices(KEYWORD) {
        let end = at + KEYWORD.len();
        let bytes = masked.as_bytes();
        if at > 0 && is_ident(bytes[at - 1]) || bytes.get(end).is_some_and(|&b| is_ident(b)) {
            continue;
        }
        if kept.iter().any(|r| r.contains(&at)) {
            continue;
        }
        out[at..end].copy_from_slice(SPELLING.as_bytes());
        changed = true;
    }
    if !changed {
        return Cow::Borrowed(source);
    }
    // Only one ASCII token was written over another, so this holds.
    Cow::Owned(String::from_utf8(out).expect("an ASCII substitution keeps UTF-8"))
}

/// Byte ranges of `source` whose spelling names something and stays as
/// written: an `#include`/`#include_next`/`#import` directive, an
/// `#if`-family condition, a `#define`'s name, and a `thread_local` macro's
/// whole definition.
fn kept_ranges(source: &str) -> Vec<Range<usize>> {
    let mut kept = Vec::new();
    for start in directive_starts(source) {
        let text = &source[start..];
        let end = start + directive_end(text);
        let keyword: String = text[1..]
            .trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '\\')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        match keyword.as_str() {
            "include" | "include_next" | "import" | "if" | "ifdef" | "ifndef" | "elif"
            | "elifdef" | "elifndef" => kept.push(start..end),
            "define" => {
                // A `thread_local` macro keeps its body too: respelled, it
                // would expand to itself.
                if let Some(define) = parse_define_directive(text) {
                    let name = start + (define.name.as_ptr() as usize - text.as_ptr() as usize);
                    let kept_end = if define.name == SPELLING.trim_end() {
                        end
                    } else {
                        name + define.name.len()
                    };
                    kept.push(name..kept_end);
                }
            }
            _ => {}
        }
    }
    kept
}

/// The respelled offsets: where `original` holds `_Thread_local` and
/// `repaired`, the text a rule read, holds the respelling.
pub fn respelled_sites(original: &str, repaired: &str) -> Vec<usize> {
    if original.len() != repaired.len() || !original.contains(KEYWORD) {
        return Vec::new();
    }
    original
        .match_indices(KEYWORD)
        .map(|(at, _)| at)
        .filter(|&at| repaired.get(at..at + SPELLING.len()) == Some(SPELLING))
        .collect()
}

/// `text` (a finding's message) with `_Thread_local` put back wherever it
/// quotes `repaired` across a respelled site in `sites`: the longest run of
/// `repaired` from the site to the end of its line that `text` contains is
/// replaced by `original` at the same offsets. A bare `thread_local ` is
/// not enough to match, since a user may have written that.
pub fn restore_spelling<'t>(
    text: &'t str,
    original: &str,
    repaired: &str,
    sites: &[usize],
) -> Cow<'t, str> {
    let mut out = Cow::Borrowed(text);
    for &at in sites {
        let line_end = repaired[at..].find('\n').map_or(repaired.len(), |k| at + k);
        for end in (at + SPELLING.len() + 1..=line_end).rev() {
            let (Some(quoted), Some(written)) = (repaired.get(at..end), original.get(at..end))
            else {
                continue;
            };
            if quoted.trim_end().len() <= SPELLING.len() {
                break;
            }
            if out.contains(quoted) {
                out = Cow::Owned(out.replacen(quoted, written, 1));
                break;
            }
        }
    }
    out
}

/// [`restore_spelling`] over a finding's message and suggestion. A no-op
/// when nothing was respelled.
pub fn restore_in_finding(
    finding: &mut crate::rules::RuleViolation,
    original: &str,
    repaired: &str,
    sites: &[usize],
) {
    if sites.is_empty() {
        return;
    }
    finding.message = restore_spelling(&finding.message, original, repaired, sites).into_owned();
    if let Some(suggestion) = &finding.suggestion {
        finding.suggestion =
            Some(restore_spelling(suggestion, original, repaired, sites).into_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_keyword_is_respelled_in_place() {
        let source = "_Thread_local int a;\nstatic _Thread_local int b;\n\
                      _Thread_local static int c;\nextern _Thread_local int d[8];\n";
        let spelled = spell_thread_local(source);
        assert_eq!(spelled.len(), source.len());
        assert_eq!(
            spelled,
            "thread_local  int a;\nstatic thread_local  int b;\n\
             thread_local  static int c;\nextern thread_local  int d[8];\n"
        );
    }

    #[test]
    fn literals_comments_and_longer_names_are_kept() {
        let source = "const char *s = \"_Thread_local\"; /* _Thread_local */\n\
                      // _Thread_local\nint my_Thread_local, _Thread_locals;\n";
        assert_eq!(spell_thread_local(source), source);
    }

    #[test]
    fn header_names_conditions_and_defined_names_are_kept() {
        let source = "#include <_Thread_local.h>\n#include_next \"_Thread_local.h\"\n\
                      #ifdef _Thread_local\n#elif defined(_Thread_local)\n#endif\n\
                      #if !defined(_Thread_local)\n#endif\n\
                      #define _Thread_local thread_local\n\
                      #define thread_local _Thread_local\n";
        assert_eq!(spell_thread_local(source), source);
    }

    #[test]
    fn a_message_quoting_a_respelled_line_is_restored() {
        let original = "static _Thread_local int x = 1, y;\nthread_local int z;\n";
        let repaired = spell_thread_local(original).into_owned();
        let sites = respelled_sites(original, &repaired);
        assert_eq!(sites, [7]);
        let message = "Declare one variable per line: thread_local  int x = 1, y;";
        assert_eq!(
            restore_spelling(message, original, &repaired, &sites),
            "Declare one variable per line: _Thread_local int x = 1, y;"
        );
        let own = "'thread_local int z' is not shared";
        assert_eq!(restore_spelling(own, original, &repaired, &sites), own);
    }

    #[test]
    fn a_macro_body_is_respelled() {
        assert_eq!(
            spell_thread_local("#define TLS _Thread_local\nTLS int x;\n"),
            "#define TLS thread_local \nTLS int x;\n"
        );
    }

    #[test]
    fn a_respelled_declaration_parses() {
        let source = spell_thread_local("static _Thread_local int counter;\n").into_owned();
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(&source, None).unwrap();
        assert!(!tree.root_node().has_error());
        let declaration = tree.root_node().child(0).unwrap();
        assert_eq!(declaration.kind(), "declaration");
        let declarator = declaration.child_by_field_name("declarator").unwrap();
        assert_eq!(&source[declarator.byte_range()], "counter");
    }
}
