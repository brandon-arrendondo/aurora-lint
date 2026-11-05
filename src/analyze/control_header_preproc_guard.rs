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
use crate::analyze::preproc_conditionals::{cond_line, match_conditionals};
use crate::analyze::range_min::MinTree;
use crate::utility::cert_c::text_bounds;
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
#[cfg(test)]
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

/// [`blank_dead_header_in`] for one block, by joining and reading its own
/// lines: what the shared tables must answer as.
#[cfg(test)]
fn blank_dead_header(
    out: &mut [u8],
    lines: &[&str],
    line_starts: &[usize],
    from: usize,
    last: usize,
) {
    let mut at = Vec::new();
    let mut offset = 0;
    for k in block_code_lines(lines, from, last) {
        at.push((k, offset));
        offset += lines[k].len() + 1;
    }
    let text = lexed_code(lines, from, last, true);
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

/// The file's code lines joined and comment-blanked once, with the braces
/// of each line counted, so a deep nest of dead blocks does not join, blank
/// and count each block's whole body again. Built on the first dead block
/// that ends with a header.
struct BlankedCode {
    /// The code lines joined with `\n`, comments blanked by [`lex_line`],
    /// so a line's code keeps its length.
    text: String,
    /// By line: where its code starts in `text`, for a directive line where
    /// the next code line's does.
    start: Vec<usize>,
    /// By line, and once more for the end: the depth of `{` before it,
    /// counting the braces outside string and character literals.
    depth: Vec<i32>,
    /// By line: the least depth it reaches.
    lowest: MinTree,
}

impl BlankedCode {
    /// `directive` says which lines are directives, as
    /// [`CodeStream::directive`] does.
    fn new(lines: &[&str], directive: &[bool]) -> BlankedCode {
        let n = lines.len();
        let mut text = String::new();
        let mut start = vec![0; n];
        let mut state = Lex::Code;
        let mut any = false;
        for (k, line) in lines.iter().enumerate() {
            if directive[k] {
                continue;
            }
            if any {
                text.push('\n');
            }
            any = true;
            start[k] = text.len();
            state = lex_line(line, state, &mut text, true);
        }
        let mut next = text.len();
        for k in (0..n).rev() {
            if directive[k] {
                start[k] = next;
            } else {
                next = start[k];
            }
        }
        let mut depth = vec![0; n + 1];
        let mut lowest = vec![0; n];
        let (mut quote, mut escaped, mut d) = (None, false, 0i32);
        for (k, line) in lines.iter().enumerate() {
            depth[k] = d;
            lowest[k] = d;
            if directive[k] {
                continue;
            }
            // The line and the `\n` after it, which ends an open literal.
            let code = &text[start[k]..start[k] + line.len()];
            for c in code.chars().chain(std::iter::once('\n')) {
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
                    '{' => d = d.saturating_add(1),
                    '}' => {
                        d = d.saturating_sub(1);
                        lowest[k] = lowest[k].min(d);
                    }
                    _ => {}
                }
            }
        }
        depth[n] = d;
        BlankedCode {
            text,
            start,
            depth,
            lowest: MinTree::new(&lowest),
        }
    }

    /// Whether the braces of lines `from..=last` pair up: they end at the
    /// depth they start at and never go below it.
    fn braces_balance(&self, from: usize, last: usize) -> bool {
        let base = self.depth[from];
        self.depth[last + 1] == base && self.lowest.min(from..last + 1) >= base
    }
}

/// Blank the header a dead block ends with, lines `from..=last` holding its
/// code: from the header's start on its first line, every code line after
/// it whole. Code before the header on that first line stays, since it may
/// close what an earlier line of the block opened. A block whose own braces
/// do not pair up is left alone: blanking part of it can only move a live
/// brace's partner. Answered from `code`. `blanked` holds, by a block's last line, where the earliest header blank
/// ending there starts: a block nested in one that blanked its header ends
/// with the same header and blanks no more of it, so it is skipped.
fn blank_dead_header_in(
    out: &mut [u8],
    (lines, line_starts, directive): (&[&str], &[usize], &[bool]),
    code: &BlankedCode,
    (from, last): (usize, usize),
    blanked: &mut std::collections::HashMap<usize, usize>,
) {
    // `from` begins in code: the stream answered for the block.
    if !code.braces_balance(from, last) {
        return;
    }
    let a = code.start[from];
    let Some(at) = dead_header_start(&code.text[a..code.start[last] + lines[last].len()]) else {
        return;
    };
    let at = a + at;
    if blanked.get(&last).is_some_and(|&done| done <= at) {
        return;
    }
    blanked.insert(last, at);
    let first = code.start.partition_point(|&s| s <= at) - 1;
    let col = at - code.start[first];
    blank_line(out, line_starts[first] + col, lines[first].len() - col);
    for k in (first + 1..=last).filter(|&k| !directive[k]) {
        blank_line(out, line_starts[k], lines[k].len());
    }
}

/// By line: whether it sits inside a backslash-continued sequence begun by
/// a preprocessor directive -- the replacement list of a multi-line
/// `#define` rather than a statement.
fn continued_directive_lines(lines: &[&str]) -> Vec<bool> {
    let mut continued = vec![false; lines.len()];
    for k in 1..lines.len() {
        let prev = lines[k - 1];
        continued[k] = prev.trim_end().ends_with('\\') && (is_directive(prev) || continued[k - 1]);
    }
    continued
}

/// The file's code lines (every line that is not a directive), joined with
/// `\n` and stripped of comments by [`lex_line`], once. A `#` line is a
/// directive only when it begins in code: inside a block comment it is
/// comment text, and is read for the `*/` that may close the comment
/// (`/* Usage:` / `#include "foo.h" */`). The lines
/// `first..=last` of one block are a slice of it, unless `first` begins
/// inside a block comment or a literal, so whether a block's code ends with a
/// control header is answered from offsets into it rather than by joining
/// and stripping each block's own code: a deep nest of blocks shares its
/// code, and that would cost time quadratic in the nest's depth.
struct CodeStream {
    /// By line: whether it is a directive, a `#` line that begins in code.
    directive: Vec<bool>,
    text: String,
    /// By line: where its code starts in `text`, for a directive line where
    /// the next code line's does.
    start: Vec<usize>,
    /// By line: whether it begins in code, not in a block comment or a
    /// continued literal.
    in_code: Vec<bool>,
    /// By line: the end of the last code that is not white space, in this
    /// line or before it.
    tail: Vec<Option<usize>>,
    /// By the `)` a code line's code ends with: what precedes the group it
    /// closes, which no block start changes.
    headers: std::collections::HashMap<usize, Option<HeaderTail>>,
}

/// What precedes a closed `(...)` group in [`CodeStream::text`].
#[derive(Clone, Copy)]
struct HeaderTail {
    /// The `(` the group opens with.
    open: usize,
    /// Where the word before the `(` starts, and what it is.
    word: usize,
    kind: HeaderWord,
}

#[derive(Clone, Copy)]
enum HeaderWord {
    /// `if` or `for`.
    Header,
    /// `while`, with the end of the code before it that is not white space.
    While(Option<usize>),
    Other,
}

impl CodeStream {
    fn new(lines: &[&str]) -> CodeStream {
        let n = lines.len();
        let mut text = String::new();
        let mut start = vec![0; n];
        let mut in_code = vec![true; n];
        let mut directive = vec![false; n];
        let mut tail = vec![None; n];
        let mut state = Lex::Code;
        let mut any = false;
        let mut last_tail = None;
        for (k, line) in lines.iter().enumerate() {
            in_code[k] = state == Lex::Code;
            directive[k] = state == Lex::Code && is_directive(line);
            if directive[k] {
                tail[k] = last_tail;
                continue;
            }
            if any && state != Lex::Comment {
                text.push('\n');
            }
            any = true;
            start[k] = text.len();
            state = lex_line(line, state, &mut text, false);
            let kept = text[start[k]..].trim_end().len();
            if kept > 0 {
                last_tail = Some(start[k] + kept);
            }
            tail[k] = last_tail;
        }
        // A directive line's start is the next code line's.
        let mut next = text.len();
        for k in (0..n).rev() {
            if directive[k] {
                start[k] = next;
            } else {
                next = start[k];
            }
        }
        let mut stream = CodeStream {
            directive,
            text,
            start,
            in_code,
            tail,
            headers: Default::default(),
        };
        stream.headers = stream.header_tails();
        stream
    }

    /// [`HeaderTail`] for each `)` a line's code ends with, from one stack
    /// pass over the parentheses. The group a `)` closes is the one a walk
    /// back from it to its `(` finds, so a block holds it only when the `(`
    /// is in the block.
    fn header_tails(&self) -> std::collections::HashMap<usize, Option<HeaderTail>> {
        let b = self.text.as_bytes();
        let wanted: std::collections::HashSet<usize> = self
            .tail
            .iter()
            .flatten()
            .map(|&e| e - 1)
            .filter(|&t| b[t] == b')')
            .collect();
        let mut tails = std::collections::HashMap::new();
        let mut opens = Vec::new();
        for (p, &c) in b.iter().enumerate() {
            match c {
                b'(' => opens.push(p),
                b')' => {
                    let open = opens.pop();
                    if wanted.contains(&p) {
                        tails.insert(p, open.map(|o| self.header_tail(o)));
                    }
                }
                _ => {}
            }
        }
        tails
    }

    fn header_tail(&self, open: usize) -> HeaderTail {
        let head = self.text[..open].trim_end();
        let word = head
            .char_indices()
            .rev()
            .find(|(_, c)| !(c.is_alphanumeric() || *c == '_'))
            .map_or(0, |(p, c)| p + c.len_utf8());
        let kind = match &head[word..] {
            "if" | "for" => HeaderWord::Header,
            "while" => {
                HeaderWord::While(Some(self.text[..word].trim_end().len()).filter(|&e| e > 0))
            }
            _ => HeaderWord::Other,
        };
        HeaderTail { open, word, kind }
    }

    /// Whether the code of lines `first..=last` ends with a control-flow
    /// header: whether [`control_header_start`] finds one in that code read
    /// from `first` by [`lex_line`]. `None` when `first` begins inside a
    /// block comment or a continued literal, where no directive before it
    /// is one and the block's code is no slice of the stream.
    fn ends_with_header(&self, first: usize, last: usize) -> Option<bool> {
        if !self.in_code[first] {
            return None;
        }
        let a = self.start[first];
        let Some(t) = self.tail[last].filter(|&e| e > a).map(|e| e - 1) else {
            return Some(false);
        };
        let Some(Some(h)) = self.headers.get(&t) else {
            return Some(false);
        };
        // The `(` and the word before it must be in the block; the block's
        // code starts a line, so a word cannot run back out of it.
        if h.open < a || h.word < a {
            return Some(false);
        }
        Some(match h.kind {
            HeaderWord::Header => true,
            HeaderWord::While(before) => before
                .filter(|&e| e > a)
                .is_none_or(|e| self.text.as_bytes()[e - 1] != b'}'),
            HeaderWord::Other => false,
        })
    }
}

/// Where a line of code begins or ends, to [`lex_line`]: in code, in a
/// block comment, or in a string or character literal a `\` ending the
/// line continues.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Lex {
    Code,
    Comment,
    Literal(char),
}

/// Append `line`, begun in `state`, to `out` without its comments: dropped,
/// or with `blank` replaced byte for byte by spaces. A `/*` or `//` inside
/// a string or character literal opens no comment (`"Accept: */*"`), so a
/// file's comments can be read once, from its start, and each line still
/// gets what a reading from its own start would give it, unless it begins
/// in a comment or a literal. How the line ends.
fn lex_line(line: &str, mut state: Lex, out: &mut String, blank: bool) -> Lex {
    let b = line.as_bytes();
    let mut i = 0;
    let mut continued = false;
    let skip = |out: &mut String, text: &str| {
        if blank {
            out.extend(std::iter::repeat_n(' ', text.len()));
        }
    };
    while i < b.len() {
        match state {
            Lex::Comment => match line[i..].find("*/") {
                Some(j) => {
                    skip(out, &line[i..i + j + 2]);
                    i += j + 2;
                    state = Lex::Code;
                }
                None => {
                    skip(out, &line[i..]);
                    return Lex::Comment;
                }
            },
            Lex::Literal(q) => {
                let ch = line[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
                if ch == '\\' {
                    match line[i..].chars().next() {
                        Some(next) => {
                            out.push(next);
                            i += next.len_utf8();
                        }
                        None => continued = true,
                    }
                } else if ch == q {
                    state = Lex::Code;
                }
            }
            Lex::Code if b[i] == b'/' && b.get(i + 1) == Some(&b'*') => {
                skip(out, "/*");
                i += 2;
                state = Lex::Comment;
            }
            Lex::Code if b[i] == b'/' && b.get(i + 1) == Some(&b'/') => {
                skip(out, &line[i..]);
                return Lex::Code;
            }
            Lex::Code => {
                let ch = line[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
                if ch == '"' || ch == '\'' {
                    state = Lex::Literal(ch);
                }
            }
        }
    }
    match state {
        // A literal the line does not continue ends with it.
        Lex::Literal(_) if !continued => Lex::Code,
        state => state,
    }
}

/// The lines of `from..=to` that are no directive, read from `from`: a `#`
/// line is one only when it begins in code.
#[cfg(test)]
fn block_code_lines(lines: &[&str], from: usize, to: usize) -> Vec<usize> {
    let mut state = Lex::Code;
    let mut kept = Vec::new();
    for (k, line) in lines.iter().enumerate().take(to + 1).skip(from) {
        if state == Lex::Code && is_directive(line) {
            continue;
        }
        kept.push(k);
        state = lex_line(line, state, &mut String::new(), false);
    }
    kept
}

/// The non-directive lines `from..=to` joined with `\n`, read by
/// [`lex_line`] from the first: comments dropped, or with `blank` blanked.
/// A `#` line is a directive only when it begins in code. What
/// [`CodeStream`] and [`BlankedCode`] hold a slice of.
#[cfg(test)]
fn lexed_code(lines: &[&str], from: usize, to: usize, blank: bool) -> String {
    let mut out = String::new();
    let mut state = Lex::Code;
    let mut any = false;
    for line in (from..=to).map(|k| lines[k]) {
        if state == Lex::Code && is_directive(line) {
            continue;
        }
        if any && (blank || state != Lex::Comment) {
            out.push('\n');
        }
        any = true;
        state = lex_line(line, state, &mut out, blank);
    }
    out
}

/// Blank the preprocessor directive lines that separate a control-flow header
/// from its body, per the module docs above. Length-preserving.
pub fn blank_control_header_guarded_preproc(source: &str) -> String {
    let (lines, line_starts) = text_bounds::lines_with_starts(source);

    let mut out = source.as_bytes().to_vec();
    // By line: whether the file proves it is never compiled. Counted by
    // where each 1-based range opens and closes, since ranges nest.
    let mut opened = vec![0i64; lines.len() + 1];
    for (s, e) in init_state::file_proven_dead_lines(source) {
        opened[s.saturating_sub(1).min(lines.len())] += 1;
        opened[e.min(lines.len())] -= 1;
    }
    let dead: Vec<bool> = opened
        .iter()
        .scan(0, |open, &d| {
            *open += d;
            Some(*open > 0)
        })
        .collect();
    let stream = CodeStream::new(&lines);
    let directive = &stream.directive;
    // A `#endif` inside a block comment closes nothing.
    let conditionals = match_conditionals(lines.len(), |k| {
        directive[k].then(|| cond_line(lines[k])).flatten()
    });
    // The last line at or before each line holding code: not blank, not a
    // directive.
    let last_code_line: Vec<Option<usize>> = lines
        .iter()
        .enumerate()
        .scan(None, |last, (k, l)| {
            if !l.trim().is_empty() && !directive[k] {
                *last = Some(k);
            }
            Some(*last)
        })
        .collect();
    let continued = continued_directive_lines(&lines);
    let mut blanked_code = None;
    let mut blanked = std::collections::HashMap::new();

    for i in 0..lines.len() {
        // No #if here, or no matching #endif (truncated snippet, or
        // unbalanced directives elsewhere in the file) -- move on rather
        // than halt the scan.
        let Some(conditional) = conditionals.at(i) else {
            continue;
        };
        let end_idx = conditional.endif;
        let has_branch = !conditional.branches.is_empty();

        // An `#else`/`#elif` arm means the two arms are alternatives; blanking
        // the wrapper would splice both into one statement stream.
        if !has_branch {
            let last = end_idx
                .checked_sub(1)
                .and_then(|k| last_code_line[k])
                .filter(|&k| k > i);

            // A block whose `#if` is inside a block comment is no
            // conditional to the compiler, and is left alone.
            let ends_with_header = last
                .filter(|&last| !continued[last])
                .and_then(|last| stream.ends_with_header(i + 1, last).map(|h| (last, h)));
            if let Some((last, true)) = ends_with_header {
                if dead[i + 1] {
                    // The header exists in no build: blank it and keep the
                    // guard, so nothing becomes its body.
                    let code =
                        blanked_code.get_or_insert_with(|| BlankedCode::new(&lines, directive));
                    let file = (&lines[..], &line_starts[..], &directive[..]);
                    let block = (i + 1, last);
                    blank_dead_header_in(&mut out, file, code, block, &mut blanked);
                } else {
                    blank_line(&mut out, line_starts[i], lines[i].len());
                    blank_line(&mut out, line_starts[end_idx], lines[end_idx].len());
                }
            }
        }

        // A nested `#if` inside this block gets its own independent check
        // on a later line.
    }

    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
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
    fn the_stream_answers_as_joining_the_block_would() {
        // Every sequence of up to four of these lines, and every block of
        // it that begins in code.
        let alphabet = [
            "#if A",
            "",
            "if (c)",
            "} while (c)",
            "while (c)",
            "c = c / 2;",
            "/* a",
            "b */ for (;;)",
            "x // if (c)",
            "f(a,",
            "b)",
            "if",
            "(c) /* z */",
            "\u{e9}if (c)",
            "p = \"/*\";",
            "q = \"*/\" /* if (c) */",
            "r = '\"'; if (c)",
            "s = \"a\\",
            "#include \"f.h\" */",
            "# x */ if (c)",
        ];
        let k = alphabet.len();
        for n in 1..=4u32 {
            for code in 0..k.pow(n) {
                let lines: Vec<&str> = (0..n).map(|p| alphabet[code / k.pow(p) % k]).collect();
                let stream = CodeStream::new(&lines);
                for last in (0..lines.len()).filter(|&l| !stream.directive[l]) {
                    for first in 0..=last {
                        let code = lexed_code(&lines, first, last, false);
                        let joined = control_header_start(&code).is_some();
                        match stream.ends_with_header(first, last) {
                            Some(found) => assert_eq!(found, joined, "{lines:?} {first}..={last}"),
                            None => assert!(!stream.in_code[first], "{lines:?} {first}"),
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_blanked_code_blanks_a_dead_header_as_its_block_would() {
        // Every sequence of up to four of these lines, and every block of
        // it, blanked alone and from the file's code.
        let alphabet = [
            "#if 0",
            "",
            "if (c)",
            "} else if (c)",
            "{ x;",
            "}",
            "/* a",
            "b */ while (c)",
            "s = \"{\\",
            "}\" // {",
            "if (a) /* { */",
            "else",
            "t = \"/*\"; if (c)",
            "u = \"*/ }\";",
            "#endif */",
            "# x */ if (c)",
        ];
        let k = alphabet.len();
        for n in 1..=4u32 {
            for code in 0..k.pow(n) {
                let lines: Vec<&str> = (0..n).map(|p| alphabet[code / k.pow(p) % k]).collect();
                let src = lines.join("\n");
                let (lines, starts) = text_bounds::lines_with_starts(&src);
                let stream = CodeStream::new(&lines);
                let blanked = BlankedCode::new(&lines, &stream.directive);
                for last in (0..lines.len()).filter(|&l| !stream.directive[l]) {
                    for from in (0..=last).filter(|&f| stream.in_code[f]) {
                        let mut alone = src.as_bytes().to_vec();
                        blank_dead_header(&mut alone, &lines, &starts, from, last);
                        let mut shared = src.as_bytes().to_vec();
                        let mut done = Default::default();
                        let block = (from, last);
                        let file = (&lines[..], &starts[..], &stream.directive[..]);
                        blank_dead_header_in(&mut shared, file, &blanked, block, &mut done);
                        assert_eq!(shared, alone, "{lines:?} {from}..={last}");
                    }
                }
            }
        }
    }

    #[test]
    fn a_hash_line_inside_a_comment_is_read_for_its_close() {
        let lines = ["/* Usage:", "#include \"foo.h\" */", "#if A", "int k;"];
        let stream = CodeStream::new(&lines);
        assert_eq!(stream.directive, [false, false, true, false]);
        assert!(stream.in_code[2] && stream.in_code[3]);
        assert_eq!(lexed_code(&lines, 0, 3, false), "\nint k;");
    }

    #[test]
    fn a_literal_a_backslash_continues_keeps_its_braces_out_of_the_depth() {
        let lines = ["s = \"ab\\", "{\";", "x;"];
        let stream = CodeStream::new(&lines);
        let code = BlankedCode::new(&lines, &stream.directive);
        assert_eq!(code.depth, [0, 0, 0, 0]);
    }

    #[test]
    fn a_comment_opener_in_a_literal_opens_no_comment() {
        let read = |lines: &[&str], blank| lexed_code(lines, 0, lines.len() - 1, blank);
        assert_eq!(
            read(&["a = \"Accept: */*\"; /* x */ b"], false),
            "a = \"Accept: */*\";  b"
        );
        assert_eq!(
            read(&["c = '/'; d = \"\\\"/*\"; // e"], false),
            "c = '/'; d = \"\\\"/*\"; "
        );
        assert_eq!(read(&["x /* a", "b */ y"], false), "x  y");
        assert_eq!(read(&["x /* a", "b */ y"], true), "x     \n     y");
        // A `\` ending the line continues the literal onto the next.
        assert_eq!(read(&["s = \"a\\", "/* b\";"], false), "s = \"a\\\n/* b\";");
        // An unterminated literal ends with its line.
        assert_eq!(read(&["s = \"a", "/* b */ c"], false), "s = \"a\n c");
    }

    #[test]
    fn a_guard_after_a_string_holding_a_comment_opener_is_still_blanked() {
        let src = "\
const char *p = \"/*\";
void f(int c){
#if A
if (c)
#endif
{ c++; }
}
";
        assert!(!unchanged(src));
        assert!(parses_clean(src));
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
