//! Pre-parse pass: repair a GNU attribute that follows an object's
//! declarator, `x __attribute__((A)) = ...`, which the grammar cannot place.
//!
//! GCC accepts an attribute after a declarator and before its initializer or
//! the `;` or `,` that ends it: `static const uint8_t blob[]
//! __attribute__((aligned(4))) = { ... };`. tree-sitter-c's grammar accepts
//! that position for a struct member, a parameter, a function declarator
//! and a typedef, but not for an object declaration. It ends the
//! declaration at the declarator with a `MISSING` `;`, puts the attribute in
//! an `ERROR` node, and reads a braced initializer after it as a compound
//! statement whose entries form a comma expression nested one level per
//! entry. A table of a few thousand entries then exceeds
//! `--max-nesting-depth` and the whole file is refused; a short one leaves
//! the object undeclared to every rule.
//!
//! The repair moves the attribute in front of the declarator, where the
//! grammar takes it as the declaration's own `attribute_specifier`, exactly
//! as for an attribute written before the declarator: `blob[]
//! __attribute__((aligned(4)))` becomes `__attribute__((aligned(4))) blob[]`.
//! A rule that reads the attribute by name (STR11-C's `nonstring`, an unused
//! annotation) still finds it in the declaration, and the declarator is the
//! plain `array_declarator` or `pointer_declarator` rules read.
//!
//! Where it cannot be moved, it is spelled as the standard attribute
//! `[[A]]`, padded with spaces to the same length, which the grammar takes
//! after a declarator (an `attributed_declarator`): for a declarator after a
//! comma, where the grammar accepts no attribute in front; for the first of
//! several declarators, where a GNU attribute moved in front would apply to
//! all of them; and where the type is written against the declarator
//! (`char*p`), which a moved attribute would fuse with. Fewer rules read
//! through an `attributed_declarator`, so the move is preferred where it
//! keeps the meaning.
//!
//! Both rewrites keep every line and its length, but not every column: the
//! swap moves the declarator right and the attribute left, and `[[A]]` moves
//! `A` left. [`rewritten_sites`] finds the rewrites again from the file's own
//! text and [`restore_in_finding`] maps a finding's column back to the token
//! it names in the file, and puts the file's own text back where a message or
//! suggestion quotes a rewritten span. Suppression and the oracle key on
//! lines, which never move.
//!
//! Only that position is rewritten: an `__attribute__`/`__attribute`
//! keyword whose previous token ends a declarator (an identifier that is not
//! a C keyword, or `]`), whose `((A))` closes on the same line, and after
//! which, past any further attributes, the next token is `=`, `;` or `,`.
//! Not after a keyword (`else __attribute__((fallthrough));` is a
//! statement), not inside parentheses (a parameter list already parses), not
//! in a struct, union or enum body (a member already parses), not in a
//! `typedef`, including after the record body a typedef declares (it already
//! parses), not after a `struct`/`union`/`enum` tag, and never on a directive
//! line. Attribute arguments are copied as written; one holding `[[` or `]]`
//! is left alone.
//!
//! Braces are read in source order without following a conditional's arms,
//! so a conditional whose arms open different numbers of braces can leave
//! the scan thinking it is in a record body: then attributes after it are
//! left alone, never rewritten where they should not be.

use crate::utility::cert_c::pp_tokens::{directive_end, directive_starts, mask_source};
use std::borrow::Cow;

const KEYWORDS: [&str; 2] = ["__attribute__", "__attribute"];

/// Words after which a `{` opens a body whose members are not object
/// declarations, and after which (as a tag's keyword) an attribute is not a
/// declarator's.
const RECORD_KEYWORDS: [&str; 3] = ["struct", "union", "enum"];

fn is_ident(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

/// One trailing attribute: the byte range of the whole
/// `__attribute__((A))` and of `A`.
struct Rewrite {
    whole: std::ops::Range<usize>,
    inner: std::ops::Range<usize>,
}

/// How one run of trailing attributes is repaired.
enum Edit {
    /// Swap the declarator at `declarator` with the attributes after it.
    Move {
        declarator: std::ops::Range<usize>,
        attributes: std::ops::Range<usize>,
    },
    /// Spell each attribute `[[A]]` in place.
    Bracket(Vec<Rewrite>),
}

const QUALIFIERS: [&str; 6] = [
    "const",
    "volatile",
    "restrict",
    "__restrict",
    "__restrict__",
    "_Atomic",
];

/// The declarator ending just before the attribute at `attr`, as a byte
/// range, when the attribute can be moved in front of it: an identifier with
/// any `[...]` suffixes, after any `*` and qualifiers, all on the
/// attribute's line; the first declarator of its declaration (not after a
/// `,`), and not written against an identifier it would fuse with.
fn movable_declarator(masked: &[u8], attr: usize) -> Option<std::ops::Range<usize>> {
    let blank = |b: u8| b == b' ' || b == b'\t';
    let mut k = attr;
    while k > 0 && blank(masked[k - 1]) {
        k -= 1;
    }
    let end = k;
    while k > 0 && masked[k - 1] == b']' {
        let mut depth = 0usize;
        loop {
            k = k.checked_sub(1)?;
            match masked[k] {
                b']' => depth += 1,
                b'[' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                b'\n' => return None,
                _ => {}
            }
        }
        while k > 0 && blank(masked[k - 1]) {
            k -= 1;
        }
    }
    let name_end = k;
    while k > 0 && is_ident(masked[k - 1]) {
        k -= 1;
    }
    if k == name_end || masked[k].is_ascii_digit() {
        return None;
    }
    loop {
        let mut m = k;
        while m > 0 && blank(masked[m - 1]) {
            m -= 1;
        }
        if m > 0 && masked[m - 1] == b'*' {
            k = m - 1;
            continue;
        }
        let word_end = m;
        while m > 0 && is_ident(masked[m - 1]) {
            m -= 1;
        }
        let word = std::str::from_utf8(&masked[m..word_end]).ok()?;
        if !word.is_empty() && QUALIFIERS.contains(&word) {
            k = m;
            continue;
        }
        break;
    }
    if k == 0 || is_ident(masked[k - 1]) {
        return None;
    }
    let mut p = k;
    while p > 0 && masked[p - 1].is_ascii_whitespace() {
        p -= 1;
    }
    (p > 0 && masked[p - 1] != b',').then_some(k..end)
}

/// The attribute starting with its keyword at `at`, if it is
/// `KEYWORD ws ( ( A ) )` closing on its own line: its whole range and the
/// range of `A`, read on the masked text.
fn attribute_at(masked: &[u8], at: usize, keyword_len: usize) -> Option<Rewrite> {
    let mut i = at + keyword_len;
    while masked.get(i).is_some_and(|b| *b == b' ' || *b == b'\t') {
        i += 1;
    }
    if masked.get(i..i + 2)? != b"((" {
        return None;
    }
    let inner_start = i + 2;
    let mut depth = 2usize;
    let mut j = inner_start;
    while depth > 0 {
        match *masked.get(j)? {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b'\n' => return None,
            _ => {}
        }
        j += 1;
    }
    // `j` is one past the second `)`; `A` ends before the first.
    let inner_end = j - 2;
    (masked[inner_end] == b')').then_some(Rewrite {
        whole: at..j,
        inner: inner_start..inner_end,
    })
}

/// C keywords. One of them before an attribute ends no declarator:
/// `else __attribute__((fallthrough));` is a statement, not a declaration.
const C_KEYWORDS: [&str; 44] = [
    "auto",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
    "_Alignas",
    "_Alignof",
    "_Atomic",
    "_Bool",
    "_Complex",
    "_Generic",
    "_Imaginary",
    "_Noreturn",
    "_Static_assert",
    "_Thread_local",
];

/// Whether the declaration continues with another declarator after the one
/// whose attributes end just before `from` (where the masked text holds the
/// `=`, `;` or `,` after them): a `,` at bracket depth 0 before the `;`.
fn more_declarators_follow(masked: &[u8], from: usize) -> bool {
    let mut depth = 0usize;
    for &b in &masked[from..] {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => return true,
            b';' if depth == 0 => return false,
            _ => {}
        }
    }
    false
}

/// Every repair the pass makes to `source`, in source order.
fn edits(source: &str) -> Vec<Edit> {
    if !source.contains("__attribute") {
        return Vec::new();
    }
    let masked_text = mask_source(source);
    let masked = masked_text.as_bytes();
    let mut in_directive = vec![false; masked.len()];
    for start in directive_starts(source) {
        let end = start + directive_end(&source[start..]);
        for flag in &mut in_directive[start..end.min(masked.len())] {
            *flag = true;
        }
    }

    let mut edits: Vec<Edit> = Vec::new();
    // Each open brace: whether it opens a record (struct/union/enum) body,
    // and the first word of the statement it sits in, which the statement
    // keeps after a record body closes (`typedef struct { ... } t ...`).
    let mut braces: Vec<(bool, Option<&str>)> = Vec::new();
    let mut parens = 0usize;
    // The last two words, the first word of the statement, and the last
    // non-blank byte, all outside directives.
    let (mut last_word, mut word_before): (&str, &str) = ("", "");
    let mut statement_first: Option<&str> = None;
    let mut last_byte = 0u8;
    let mut i = 0;
    while i < masked.len() {
        if in_directive[i] {
            i += 1;
            continue;
        }
        let b = masked[i];
        if is_ident(b) && !(i > 0 && is_ident(masked[i - 1]) && !in_directive[i - 1]) {
            let start = i;
            while i < masked.len() && is_ident(masked[i]) && !in_directive[i] {
                i += 1;
            }
            let word = &masked_text[start..i];
            if KEYWORDS.contains(&word) {
                let declarator_ends = (last_byte == b']'
                    || (is_ident(last_byte) && !C_KEYWORDS.contains(&last_word)))
                    && !RECORD_KEYWORDS.contains(&word_before);
                let in_record = braces.last().is_some_and(|(record, _)| *record);
                if declarator_ends
                    && parens == 0
                    && !in_record
                    && statement_first != Some("typedef")
                {
                    if let Some((chain, after)) = attribute_chain(masked, &in_directive, start) {
                        if matches!(masked.get(after), Some(b'=' | b';' | b',')) {
                            i = chain.last().map_or(i, |r| r.whole.end);
                            // Moved off the first of several declarators, a
                            // GNU attribute would apply to all of them.
                            let movable = movable_declarator(masked, start)
                                .filter(|_| !more_declarators_follow(masked, after));
                            edits.push(match movable {
                                Some(declarator) => Edit::Move {
                                    declarator,
                                    attributes: start..i,
                                },
                                None => Edit::Bracket(chain),
                            });
                            last_byte = b')';
                            continue;
                        }
                    }
                }
            }
            word_before = last_word;
            last_word = word;
            statement_first.get_or_insert(word);
            last_byte = masked[i - 1];
            continue;
        }
        match b {
            b'{' => {
                let record = RECORD_KEYWORDS.contains(&last_word)
                    || (is_ident(last_byte) && RECORD_KEYWORDS.contains(&word_before));
                braces.push((record, statement_first));
                statement_first = None;
            }
            b'}' => {
                statement_first = match braces.pop() {
                    Some((true, outer)) => outer,
                    _ => None,
                };
            }
            b';' => statement_first = None,
            b'(' => parens += 1,
            b')' => parens = parens.saturating_sub(1),
            _ => {}
        }
        if !b.is_ascii_whitespace() {
            last_byte = b;
            if !is_ident(b) {
                // A punctuator ends the run of words a tag check reads.
                if b != b'*' {
                    word_before = "";
                    last_word = "";
                }
            }
        }
        i += 1;
    }
    edits
}

/// The bytes `edit` writes over its span of `source`, and the span.
fn rewrite(source: &str, edit: &Edit) -> (std::ops::Range<usize>, String) {
    match edit {
        Edit::Move {
            declarator,
            attributes,
        } => (
            // `D gap A` becomes `A gap D`: the same bytes in a new order.
            declarator.start..attributes.end,
            [
                &source[attributes.clone()],
                &source[declarator.end..attributes.start],
                &source[declarator.clone()],
            ]
            .concat(),
        ),
        Edit::Bracket(chain) => {
            let span = chain[0].whole.start..chain[chain.len() - 1].whole.end;
            let mut text = source[span.clone()].to_string();
            for r in chain.iter().rev() {
                let inner = &source[r.inner.clone()];
                let spelled = format!("[[{inner}]]");
                let padded = format!("{spelled:<width$}", width = r.whole.len());
                text.replace_range(
                    r.whole.start - span.start..r.whole.end - span.start,
                    &padded,
                );
            }
            (span, text)
        }
    }
}

/// `source` with each GNU attribute that trails an object's declarator moved
/// in front of it, or spelled as a standard attribute where it cannot move.
pub fn spell_trailing_attributes(source: &str) -> Cow<'_, str> {
    let edits = edits(source);
    if edits.is_empty() {
        return Cow::Borrowed(source);
    }
    let mut out = source.as_bytes().to_vec();
    for edit in &edits {
        let (span, text) = rewrite(source, edit);
        out[span].copy_from_slice(text.as_bytes());
    }
    // Whole tokens were reordered or ASCII written over whole tokens, and
    // every boundary moved is between tokens, never inside a character.
    Cow::Owned(String::from_utf8(out).expect("a token-level reordering keeps UTF-8"))
}

/// One place the pass rewrote, as found in a file's own text and its
/// repaired text.
pub struct RewrittenSite {
    span: std::ops::Range<usize>,
    /// For a moved attribute, the lengths of the declarator, the blank
    /// between, and the attributes, in the file's own order.
    swap: Option<(usize, usize, usize)>,
    /// For an attribute spelled `[[A]]` in place, each `A` that moved left:
    /// where it starts in the repaired text, where in the file, and its
    /// length. Everything else in the span is the spelling itself.
    respelled: Vec<(usize, usize, usize)>,
}

/// Every site where `repaired` holds this pass's rewrite of `original`. The
/// pass is run again on the file's own text, and a rewrite is kept only
/// where the repaired text shows exactly those bytes, so a site another pass
/// also touched is skipped rather than mapped wrongly.
pub fn rewritten_sites(original: &str, repaired: &str) -> Vec<RewrittenSite> {
    if original.len() != repaired.len() {
        return Vec::new();
    }
    edits(original)
        .iter()
        .filter_map(|edit| {
            let (span, text) = rewrite(original, edit);
            (repaired.get(span.clone()) == Some(text.as_str())).then(|| RewrittenSite {
                respelled: match edit {
                    Edit::Bracket(chain) => chain
                        .iter()
                        .map(|r| (r.whole.start + 2, r.inner.start, r.inner.len()))
                        .collect(),
                    Edit::Move { .. } => Vec::new(),
                },
                swap: match edit {
                    Edit::Move {
                        declarator,
                        attributes,
                    } => Some((
                        declarator.len(),
                        attributes.start - declarator.end,
                        attributes.len(),
                    )),
                    Edit::Bracket(_) => None,
                },
                span,
            })
        })
        .collect()
}

/// `finding` as the file's own text has it: a column inside a moved
/// declaration points at the same token in the file, and text the message or
/// suggestion quotes from a rewritten span reads as written.
pub fn restore_in_finding(
    finding: &mut crate::rules::RuleViolation,
    original: &str,
    repaired: &str,
    sites: &[RewrittenSite],
) {
    if sites.is_empty() {
        return;
    }
    let line_start = original
        .split_inclusive('\n')
        .take(finding.line.saturating_sub(1))
        .map(str::len)
        .sum::<usize>();
    let at = line_start + finding.column.saturating_sub(1);
    for site in sites {
        if let Some((d, gap, a)) = site.swap {
            if site.span.contains(&at) {
                // The repaired span reads `A gap D`; the file reads `D gap A`.
                let p = at - site.span.start;
                let mapped = if p < a {
                    d + gap + p
                } else if p < a + gap {
                    d + (p - a)
                } else {
                    p - a - gap
                };
                finding.column = site.span.start + mapped - line_start + 1;
            }
        }
        // Inside `[[A]]`, `A` sits where `__attribute__((A))` had its keyword.
        if let Some(&(from, to, _)) = site
            .respelled
            .iter()
            .find(|(from, _, len)| (*from..from + len).contains(&at))
        {
            finding.column = to + (at - from) - line_start + 1;
        }
        let rewritten = &repaired[site.span.clone()];
        let written = &original[site.span.clone()];
        if finding.message.contains(rewritten) {
            finding.message = finding.message.replace(rewritten, written);
        }
        if let Some(s) = finding
            .suggestion
            .as_mut()
            .filter(|s| s.contains(rewritten))
        {
            *s = s.replace(rewritten, written);
        }
    }
}

/// The attributes in a row starting with the keyword at `at`, and the offset
/// of the first non-blank byte after them, when every one closes on its own
/// line and none holds `[[` or `]]` in its arguments.
fn attribute_chain(
    masked: &[u8],
    in_directive: &[bool],
    at: usize,
) -> Option<(Vec<Rewrite>, usize)> {
    let mut chain = Vec::new();
    let mut k = at;
    loop {
        let keyword = KEYWORDS
            .iter()
            .find(|kw| masked[k..].starts_with(kw.as_bytes()))?;
        if masked.get(k + keyword.len()).is_some_and(|b| is_ident(*b)) {
            return None;
        }
        let r = attribute_at(masked, k, keyword.len())?;
        let inner = &masked[r.inner.clone()];
        if inner.windows(2).any(|w| w == b"[[" || w == b"]]") {
            return None;
        }
        k = r.whole.end;
        chain.push(r);
        while masked.get(k).is_some_and(|b| b.is_ascii_whitespace()) {
            k += 1;
        }
        if in_directive.get(k).copied().unwrap_or(false)
            || !KEYWORDS
                .iter()
                .any(|kw| masked[k..].starts_with(kw.as_bytes()))
        {
            return Some((chain, k));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::c_language;

    fn spelled(src: &str) -> String {
        let out = spell_trailing_attributes(src).into_owned();
        assert_eq!(src.len(), out.len(), "byte length changed");
        assert_eq!(src.matches('\n').count(), out.matches('\n').count());
        out
    }

    fn parses_clean(src: &str) -> bool {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&c_language()).unwrap();
        !parser.parse(src, None).unwrap().root_node().has_error()
    }

    #[test]
    fn moves_an_attribute_in_front_of_its_declarator() {
        let src = "\
static const unsigned char blob[] __attribute__((aligned(4))) = { 1, 2, 3 };
char tag[3] __attribute__((nonstring)) = \"abc\";
int f(void) { int v __attribute__((unused)) = 1; return v; }
char sec[4] __attribute__((section(\".rodata\"))) = \"abc\";
struct s { int a; } v __attribute__((aligned(16))) = { 0 };
int w __attribute__((unused)) __attribute__((aligned(4))) = 0;
char * const p __attribute__((unused)) = 0;
";
        assert!(!parses_clean(src));
        let out = spelled(src);
        assert!(parses_clean(&out), "{out}");
        for moved in [
            "char __attribute__((aligned(4))) blob[] =",
            "char __attribute__((nonstring)) tag[3] =",
            "int __attribute__((unused)) v =",
            "char __attribute__((section(\".rodata\"))) sec[4] =",
            "} __attribute__((aligned(16))) v =",
            "int __attribute__((unused)) __attribute__((aligned(4))) w =",
            "char __attribute__((unused)) * const p =",
        ] {
            assert!(out.contains(moved), "{moved} missing:\n{out}");
        }
    }

    #[test]
    fn spells_an_attribute_it_cannot_move_as_a_standard_one() {
        // A first declarator with more after it: moved in front, a GNU
        // attribute would apply to every declarator of the declaration.
        let src = "\
static int c __attribute((unused)), d __attribute__((unused));
int e __attribute__((unused)) = 1, f;
char*q __attribute__((unused)) = 0;
";
        let out = spelled(src);
        assert!(parses_clean(&out), "{out}");
        assert!(out.starts_with("static int c [[unused]]"), "{out}");
        assert!(out.contains(", d [[unused]]"), "{out}");
        assert!(out.contains("int e [[unused]]"), "{out}");
        assert!(out.contains("char*q [[unused]]"), "{out}");
        assert!(!out.contains("__attribute"), "{out}");
    }

    #[test]
    fn leaves_a_typedef_of_a_record_and_a_keyword_alone() {
        let src = "\
typedef struct { int z; } boxed __attribute__((aligned(16)));
typedef union { int z; float f; } either __attribute__((aligned(8)));
void g(int x) {
    switch (x) {
    case 1:
        if (x) { x++; } else __attribute__((fallthrough));
    default:
        return __attribute__((unused)) ;
    }
}
";
        assert_eq!(spell_trailing_attributes(src), src);
    }

    /// The finding a rule would make at `needle` in `repaired`, restored.
    fn restored(original: &str, needle: &str, message: &str) -> crate::rules::RuleViolation {
        let repaired = spelled(original);
        let at = repaired.find(needle).expect("needle in the repaired text");
        let line_start = repaired[..at].rfind('\n').map_or(0, |n| n + 1);
        let mut v = crate::rules::RuleViolation {
            line: repaired[..at].matches('\n').count() + 1,
            column: at - line_start + 1,
            message: message.to_string(),
            ..Default::default()
        };
        let sites = rewritten_sites(original, &repaired);
        restore_in_finding(&mut v, original, &repaired, &sites);
        v
    }

    #[test]
    fn a_finding_in_a_moved_declaration_is_restored_to_the_file() {
        let original = "\
int x;
static const unsigned char tbl[] __attribute__((aligned(16))) = { 1, 2 };
";
        let column_in = |needle: &str| original.lines().nth(1).unwrap().find(needle).unwrap() + 1;
        // At the declarator: its own column, not the attribute's.
        let v = restored(original, "tbl[]", "tbl");
        assert_eq!((v.line, v.column), (2, column_in("tbl[]")));
        // Inside the attribute: the same token in the file.
        let v = restored(original, "16", "");
        assert_eq!(v.column, column_in("16"));
        // At the blank between them.
        let repaired = spelled(original);
        let blank = repaired.find(")) tbl").unwrap() + 2;
        let v = restored(original, &repaired[blank..blank + 4], "");
        assert_eq!(v.column, column_in(" __attribute__"));
        // Quoted text reads as the file has it.
        let quoted = &repaired.lines().nth(1).unwrap()[..70];
        let v = restored(original, "tbl[]", &format!("declaration '{quoted}'"));
        assert_eq!(
            v.message,
            format!("declaration '{}'", &original.lines().nth(1).unwrap()[..70])
        );
        // Off the rewritten span, nothing moves.
        let v = restored(original, "int x", "");
        assert_eq!((v.line, v.column), (1, 1));
    }

    #[test]
    fn a_finding_quoting_a_standard_spelling_reads_the_file_s() {
        let original = "int a __attribute__((unused)), b = 1;\n";
        let repaired = spelled(original);
        let v = restored(
            original,
            "a [[",
            &format!("declares '{}'", repaired.trim_end()),
        );
        assert_eq!(v.message, format!("declares '{}'", original.trim_end()));
        assert_eq!(v.column, original.find("a __").unwrap() + 1);
        // Inside the attribute: the same token in the file.
        let v = restored(original, "unused", "");
        assert_eq!(v.column, original.find("unused").unwrap() + 1);
    }

    #[test]
    fn leaves_positions_that_already_parse_alone() {
        let src = "\
struct s { int a __attribute__((aligned(8))); } __attribute__((packed));
struct __attribute__((packed)) t { int b; };
int f(int x __attribute__((unused)), int y);
void g(void) __attribute__((noreturn));
void (*fp)(int) __attribute__((unused)) = 0;
typedef int myint __attribute__((aligned(8)));
enum e { E_A __attribute__((deprecated)), E_B };
#define ALIGNED(n) x __attribute__((aligned(n))) = 0
/* int z __attribute__((unused)) = 1; */
const char *s = \"q __attribute__((unused)) = 1;\";
";
        assert_eq!(spell_trailing_attributes(src), src);
    }

    #[test]
    fn leaves_an_attribute_that_does_not_close_on_its_line_alone() {
        let src = "int x __attribute__((aligned(\n4))) = 0;\n";
        assert_eq!(spell_trailing_attributes(src), src);
    }

    #[test]
    fn a_large_table_parses_flat() {
        let entries: Vec<String> = (0..6000).map(|n| format!("0x{:02x}", n % 256)).collect();
        let src = format!(
            "static const unsigned char blob[] __attribute__((aligned(4))) = {{ {} }};\n",
            entries.join(", ")
        );
        let out = spelled(&src);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(&out, None).unwrap();
        assert!(!tree.root_node().has_error());
        let list = crate::analyze::input_guard::admit_tree(&tree);
        assert!(list.is_ok(), "a flat table is admitted");
    }
}
