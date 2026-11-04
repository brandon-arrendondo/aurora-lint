//! Iterative parse-error recovery for unknown bare identifiers that have no
//! local `#define` (a follow-up to the `empty_macro_blank` pass below).
//!
//! An earlier fix fixed the WINAPI/RLAPI-style export-macro idiom by blanking a
//! name that's locally `#define`d to nothing. That approach has nothing to
//! find when the offending identifier comes from an *external* header not
//! included in a single-file parse -- e.g. raylib's rlgl.h uses
//! `GL_APIENTRYP`/`GLAPIENTRY` (calling-convention macros from glad/GL
//! headers) inside function-pointer typedefs like
//! `typedef void (GL_APIENTRYP PFNGLFOO)(...)`, with no local `#define` for
//! either name.
//!
//! Rather than guess by naming convention (all-caps, `*API*` substring,
//! etc. -- too easy to also match a meaningful enum-like macro constant),
//! this uses the parser's OWN failure signal: after an initial parse, if
//! tree-sitter isolates a single bare-identifier token as its own leaf
//! `ERROR` node (no children, and its text -- trimmed -- is exactly one C
//! identifier), that is direct, precise evidence this exact token could not
//! be integrated into the surrounding declaration. Blanking exactly that
//! occurrence (not every occurrence of the name file-wide, unlike task
//! 435 -- a single bad token doesn't imply every other occurrence of that
//! name is also unresolvable) and re-parsing is a safe recovery: whatever
//! was inside that ERROR node was already inaccessible to every AST-based
//! rule query, so removing it can only ever recover structure, never lose
//! anything a rule could have used.
//!
//! Bounded to a small number of iterations -- each is a full re-parse -- so
//! a pathological file can't spin forever; recovery stops as soon as a pass
//! finds no more single-token identifier ERROR nodes, whether or not
//! `has_error()` has fully cleared (some files may have unrelated parse
//! issues this pass isn't meant to touch).
//!
//! An earlier fix made the choice of WHICH token to blank macro-aware. Blanking
//! the stranded token is right only when that token really is the macro the
//! parser could not place; in `MACRO type f(...)` shapes tree-sitter instead
//! strands the *type* (`CURL_EXTERN CURLcode curl_easy_setopt(...)` strands
//! `CURLcode`, `Tcl_Obj *CONST objv[]` strands `objv`), so blanking it threw
//! away real code and left the macro standing as the type -- every rule
//! downstream then read a wrong type or a wrong declared name. Measured over
//! the nine pinned real-world checkouts before the fix: 686 of 1574 blanks
//! landed inside a declaration, and 328 of those blanked a real identifier
//! whose immediately preceding token was a known project macro. When the
//! prescan's object-like macro table is available (see [`RepairMacros`]),
//! that preceding macro is blanked instead -- but only if re-parsing that
//! way is no worse than re-parsing the original blank, so the parser's own
//! failure signal still has the last word. With no macro table (prescan
//! itself, single-file callers, tests) the pass behaves exactly as before.
//!
//! An earlier fix added a second, differently-shaped recovery target to the same
//! loop: a lone `{`/`}` ERROR-wrapped inside a `#if defined(__cplusplus)`
//! (or `#ifdef`/`#elif`) conditional -- the dual-C/C++-header idiom for
//! guarding an `extern "C"` block's open/close brace. See
//! `find_blankable_preproc_brace_error` for why this one small, locally
//! contained defect was observed cascading into a file-spanning ERROR node
//! on raylib's rlgl.h.

use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::{Node, Parser, Tree};

use crate::analyze::context::ProjectContext;

/// Project-wide macro knowledge the repair pass consults when deciding which
/// token to blank. Empty means "no prescan data" -- every decision then
/// falls back to the token tree-sitter stranded, which is what this pass did
/// before an earlier fix.
#[derive(Debug, Default, Clone)]
pub struct RepairMacros {
    /// Every `#define NAME ...` name seen project-wide
    /// ([`ProjectContext::defined_macro_names`]). A token in here cannot be
    /// the declaration's real type or declarator, so it is the safe thing to
    /// blank when it sits next to one the parser could not place.
    pub object_macros: HashSet<String>,
    /// Object-like macros expanding to an unused-attribute annotation
    /// ([`ProjectContext::unused_attribute_macros`]). Blanking one destroys
    /// the author's "may go unused" statement before any rule can read it,
    /// so these leave [`UNUSED_ATTRIBUTE_MARKER`] behind instead.
    pub unused_attribute_macros: HashSet<String>,
    /// Object-like macros some project file defines as a storage class,
    /// with the files defining each
    /// ([`ProjectContext::storage_class_macros`]).
    pub storage_class_macros: Arc<crate::analyze::storage_class_macro::StorageClassTable>,
    /// The include graph ([`ProjectContext::include_edges`]) that says which
    /// of those files a file can see.
    pub include_edges: Arc<HashMap<String, Vec<String>>>,
    /// Object-like macros whose expansion means something a rule reads off
    /// the name: a storage class or `static inline`
    /// ([`ProjectContext::static_macro_names`], [`Self::storage_class_macros`]),
    /// a noreturn attribute ([`ProjectContext::attribute_noreturn_macros`],
    /// [`ProjectContext::keyword_noreturn_macros`]) or an unused attribute.
    /// An annotation taken for a declaration's type is never blanked when it
    /// is one of these: the rules resolve it by name, and a blank leaves
    /// them nothing to resolve.
    pub meaningful_macros: HashSet<String>,
}

impl RepairMacros {
    /// The two macro sets the prescan already collects, copied out of a
    /// [`ProjectContext`].
    pub fn from_context(context: &ProjectContext) -> Self {
        Self {
            object_macros: HashSet::clone(&context.defined_macro_names),
            unused_attribute_macros: HashSet::clone(&context.unused_attribute_macros),
            storage_class_macros: Arc::clone(&context.storage_class_macros),
            include_edges: Arc::clone(&context.include_edges),
            meaningful_macros: context
                .static_macro_names
                .iter()
                .chain(context.attribute_noreturn_macros.iter())
                .chain(context.keyword_noreturn_macros.iter())
                .chain(context.unused_attribute_macros.iter())
                .chain(context.storage_class_macros.keys())
                .cloned()
                .collect(),
        }
    }
}

/// Marker written in place of a blanked [`RepairMacros::unused_attribute_macros`]
/// token, the same length-preserving recoverable-marker idiom an earlier fix uses
/// for label-guarded directives and an earlier fix for `NORETURN`. Without it the
/// declaration reaching MSC13-C reads `word_t totalObjectSize       ;` --
/// correctly parsed, correctly named, and with the annotation that makes it
/// legitimate silently gone. Consumers must accept it both
/// inside the declaration's own span and immediately before it, since the
/// macro can sit on either side of the type.
pub const UNUSED_ATTRIBUTE_MARKER: &str = "/*U*/";

/// Each iteration is a full re-parse of the file; capped to bound worst-case
/// cost on a pathological input. Real files have needed at most a handful
/// of passes in testing (one distinct unknown-identifier name per pass, in
/// source order).
const MAX_ITERATIONS: u32 = 8;

/// A C keyword must never be blanked even when tree-sitter's error recovery
/// leaves one wrapped in a generic `identifier` leaf inside an `ERROR` node.
/// Found via a real regression: `STATIC void f(...) {}` (`STATIC` a real,
/// non-empty macro for `static`) parsed with `STATIC` consumed as the
/// declarator's `type_identifier` and `void` itself stranded as an
/// ERROR-wrapped `identifier` -- blanking "void" as if it were an unknown
/// macro discarded the function's actual return type, which then made
/// MSC37-C misjudge it as non-void and demand a return statement. A keyword
/// being inside an ERROR node is a sign the SURROUNDING structure misparsed,
/// not that the keyword itself is safely removable.
use crate::utility::cert_c::ast_utils::is_c_keyword;

fn is_bare_identifier(text: &str) -> bool {
    if is_c_keyword(text) {
        return false;
    }
    let mut chars = text.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Depth-first search for the first leaf `ERROR` node whose trimmed text is
/// a single bare identifier. Returns the exact (untrimmed-boundary) byte
/// range to blank.
///
/// Walks with a cursor ([`query::find_first_descendant`]), never by
/// `node.child(i)` in a loop. tree-sitter's `child(i)` starts
/// from the first child every call, so an index loop costs O(n²) per node
/// -- invisible on a normal tree, but a NUL-interleaved (mis-decoded
/// UTF-16, or binary) file parses to ONE root `ERROR` node with tens of
/// thousands of direct children (56,175 on Ventoy2Disk's WinDialog.c), and
/// that one loop ran for over ten minutes before being killed. Every walk
/// in this module is cursor-based for the same reason: this pass runs
/// before any rule and with every rule disabled, so it must stay linear on
/// exactly the inputs the parser recovers worst from.
fn find_blankable_identifier_error(node: &Node, source: &str) -> Option<(usize, usize)> {
    // Deliberately matched on the ERROR node's own text span, not its
    // internal child structure: tree-sitter sometimes wraps the offending
    // token in its own `identifier` child rather than leaving the ERROR
    // node itself childless (observed for `PFNGLFOO` in
    // `(GL_APIENTRYP PFNGLFOO)` -- the ERROR node has one `identifier`
    // child, GL_APIENTRYP itself parsed fine as a `type_identifier`). What
    // matters is only that the ERROR node's entire span is exactly one bare
    // identifier once trimmed, regardless of how many (or few) children it
    // has internally.
    let found = query::find_first_descendant(*node, |n| {
        n.kind() == "ERROR" && {
            let trimmed = source[n.start_byte()..n.end_byte()].trim();
            !trimmed.is_empty() && is_bare_identifier(trimmed)
        }
    })?;
    let start = found.start_byte();
    let end = found.end_byte();
    let text = &source[start..end];
    let leading = text.len() - text.trim_start().len();
    let trailing = text.len() - text.trim_end().len();
    Some((start + leading, end - trailing))
}

fn blank_range(source: &str, start: usize, end: usize) -> String {
    let mut bytes = source.as_bytes().to_vec();
    for b in bytes.iter_mut().take(end).skip(start) {
        // Newlines are preserved even inside a blanked range (an earlier fix's
        // preproc-brace recovery blanks a whole directive line, including
        // the newline that separates it from the brace) so line numbers
        // downstream never shift.
        if *b != b'\n' && *b != b'\r' {
            *b = b' ';
        }
    }
    // Safe: only ASCII identifier bytes (already validated by
    // `is_bare_identifier`) are replaced with ASCII spaces.
    String::from_utf8(bytes).unwrap_or_else(|_| source.to_string())
}

/// Same as [`blank_range`], but an unused-attribute macro (resolved through
/// the prescan's [`RepairMacros::unused_attribute_macros`] rather than by
/// spelling) leaves [`UNUSED_ATTRIBUTE_MARKER`] behind: what the macro
/// expanded to is the author's statement that the variable may go unread,
/// and blanking it hands MSC13-C a declaration with nothing left to read.
/// Every other unknown identifier is blanked.
fn blank_or_mark(source: &str, start: usize, end: usize, macros: &RepairMacros) -> String {
    let trimmed = source[start..end].trim();
    if macros.unused_attribute_macros.contains(trimmed) {
        if let Some(marked) = write_padded_marker(source, start, end, UNUSED_ATTRIBUTE_MARKER) {
            return marked;
        }
    }
    blank_range(source, start, end)
}

/// Write `marker` into `source[start..end]`, right-padded with spaces to
/// preserve the original byte length. `None` when the marker doesn't fit --
/// a macro name shorter than the marker just gets a plain blank, exactly as
/// before.
fn write_padded_marker(source: &str, start: usize, end: usize, marker: &str) -> Option<String> {
    let len = end - start;
    if len < marker.len() {
        return None;
    }
    let mut out = String::with_capacity(source.len());
    out.push_str(&source[..start]);
    out.push_str(marker);
    out.push_str(&" ".repeat(len - marker.len()));
    out.push_str(&source[end..]);
    Some(out)
}

/// The known object-like macro tokens standing in front of `start` within
/// the same run of whitespace-separated words, nearest first.
///
/// This is the `MACRO type declarator` shape (curl's
/// `CURL_EXTERN CURLcode curl_easy_setopt(...)`, seL4's
/// `UNUSED pptr_t vaddr = ...`): whatever the parser stranded, the macro is
/// the token that genuinely cannot be there, so it is the one to blank. The
/// macro is not always the immediate predecessor -- in the seL4 shape the
/// type sits between it and the stranded declarator -- so the whole run is
/// walked, capped at [`MAX_PRECEDING_TOKENS`] words.
///
/// Deliberately strict about what may sit between two words. Anything that
/// is not whitespace -- a `;`, a `)`, a `,`, a `#`, the tail of a comment --
/// ends the backward scan, which keeps this from reaching across a
/// statement boundary or into an unrelated construct. A macro on a
/// preprocessor line of its own (`#define X Y`, where `X` is by definition a
/// known macro name) is rejected outright: blanking it would destroy the
/// definition the prescan reads.
fn preceding_macro_tokens(
    source: &str,
    start: usize,
    macros: &RepairMacros,
) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut found = Vec::new();
    let mut i = start;
    for _ in 0..MAX_PRECEDING_TOKENS {
        let scan_from = i;
        while i > 0 && (bytes[i - 1] as char).is_ascii_whitespace() {
            i -= 1;
        }
        let token_end = i;
        if token_end == scan_from {
            // Nothing separates this position from the previous word, so
            // there is no further word to consider.
            break;
        }
        while i > 0 && ((bytes[i - 1] as char).is_ascii_alphanumeric() || bytes[i - 1] == b'_') {
            i -= 1;
        }
        let token_start = i;
        if token_start == token_end {
            break;
        }
        let token = &source[token_start..token_end];
        if is_bare_identifier(token)
            && macros.object_macros.contains(token)
            && !line_is_preprocessor_directive(source, token_start)
        {
            found.push((token_start, token_end));
        }
    }
    found
}

/// How far back [`preceding_macro_tokens`] looks for the macro. A
/// declaration's macro sits at most a type and a qualifier or two away from
/// the token the parser stranded; every extra word is another candidate
/// re-parse for no observed gain.
const MAX_PRECEDING_TOKENS: usize = 4;

/// Type-specifier keywords: one of these stranded by the parser (wrapped in an
/// `ERROR`, or read as a declarator `identifier`) means a declaration already
/// had its type when the parser reached it.
const TYPE_SPECIFIER_KEYWORDS: &[&str] = &[
    "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool",
    "_Complex", "struct", "union", "enum",
];

/// The keywords that may stand between a declaration's leading type and its
/// type specifier without being a type themselves: storage classes, function
/// specifiers and qualifiers.
const NON_TYPE_SPECIFIER_KEYWORDS: &[&str] = &[
    "static",
    "extern",
    "register",
    "auto",
    "inline",
    "__inline",
    "__inline__",
    "_Noreturn",
    "thread_local",
    "__thread",
    "const",
    "volatile",
    "restrict",
];

/// The word ending at `end` (identifier characters only), as a byte range.
fn word_before(bytes: &[u8], end: usize) -> Option<(usize, usize)> {
    let mut start = end;
    while start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
        start -= 1;
    }
    (start < end).then_some((start, end))
}

/// Skip whitespace backwards from `at`; the position after the last
/// non-whitespace byte.
fn skip_space_back(bytes: &[u8], mut at: usize) -> usize {
    while at > 0 && bytes[at - 1].is_ascii_whitespace() {
        at -= 1;
    }
    at
}

/// Whether a declaration may begin right after `at`: the start of the file,
/// the end of a statement, declaration or block (`;`, `{`, `}`), or the end
/// of a preprocessor directive's line. Read in `masked`, the source with
/// comments and literal contents blanked ([`pp_tokens::mask_source`]), so a
/// comment of either kind between the two counts as whitespace: `int x;` /
/// `// doc` / `CHECKED`. `source` decides what is a directive.
///
/// [`pp_tokens::mask_source`]: crate::utility::cert_c::pp_tokens::mask_source
fn declaration_may_start_after(source: &str, masked: &str, at: usize) -> bool {
    let bytes = masked.as_bytes();
    let before = skip_space_back(bytes, at);
    if before == 0 {
        return true;
    }
    if matches!(bytes[before - 1], b';' | b'{' | b'}') {
        return true;
    }
    // Only whitespace, and at least one line break, between a directive's
    // end and `at`; a directive continued with `\` ends on its last line.
    masked[before..at].contains('\n') && in_preprocessor_directive(source, before - 1)
}

/// True if the line containing `byte` is a preprocessor directive's, its
/// first or one it continues onto with a trailing `\`.
fn in_preprocessor_directive(source: &str, byte: usize) -> bool {
    let mut line_start = source[..byte].rfind('\n').map_or(0, |i| i + 1);
    while line_start > 0
        && source[..line_start - 1]
            .trim_end_matches('\r')
            .ends_with('\\')
    {
        line_start = source[..line_start - 1].rfind('\n').map_or(0, |i| i + 1);
    }
    source[line_start..].trim_start().starts_with('#')
}

/// Annotation macros the parser took for a declaration's type: in
/// `MBEDTLS_CHECK_RETURN_CRITICAL` / `static int f(void)` the unknown name
/// becomes the `type_identifier`, `static` a storage class, and the real
/// type `int` is stranded in an `ERROR` (or, for `unsigned` or `struct`,
/// read as the declarator, with the rest of the declaration lost). The
/// existing repairs cannot help: a stranded keyword is never blanked,
/// since it is real code, and the name is a macro only the prescan might
/// know.
///
/// Read off the parser's signal, not a name: a type-specifier keyword the
/// parser stranded, preceded, across only whitespace and storage-class,
/// function-specifier or qualifier keywords, by one identifier that begins
/// the declaration. A declaration has one type, so that identifier cannot be
/// it whatever it names; it is what a preprocessor would have replaced with
/// an attribute or nothing, and blanking it hands the declaration back its
/// type. Returns every such identifier's byte range, each once.
fn find_annotation_taken_for_type(node: &Node, source: &str) -> Vec<(usize, usize)> {
    let stranded = query::find_descendants(*node, |n| {
        let text = source[n.start_byte()..n.end_byte()].trim();
        TYPE_SPECIFIER_KEYWORDS.contains(&text)
            && (n.kind() == "ERROR"
                || (n.kind() == "identifier"
                    && n.parent()
                        .is_some_and(|p| matches!(p.kind(), "declaration" | "ERROR"))))
    });
    if stranded.is_empty() {
        return Vec::new();
    }
    // Every backward scan reads the masked source, so a comment between the
    // annotation and what precedes or follows it reads as whitespace:
    // `CHECKED // note` / `static int f(void)`.
    let masked = crate::utility::cert_c::pp_tokens::mask_source(source);
    let bytes = masked.as_bytes();
    let mut found: Vec<(usize, usize)> = Vec::new();
    for n in stranded {
        let text = &source[n.start_byte()..n.end_byte()];
        let mut at = n.start_byte() + (text.len() - text.trim_start().len());
        let candidate = loop {
            at = skip_space_back(bytes, at);
            let Some((start, end)) = word_before(bytes, at) else {
                break None;
            };
            let word = &source[start..end];
            if NON_TYPE_SPECIFIER_KEYWORDS.contains(&word) {
                at = start;
                continue;
            }
            break Some((start, end));
        };
        let Some((start, end)) = candidate else {
            continue;
        };
        if is_bare_identifier(&source[start..end])
            && !line_is_preprocessor_directive(source, start)
            && declaration_may_start_after(source, &masked, start)
            && !found.contains(&(start, end))
        {
            found.push((start, end));
        }
    }
    found
}

/// True if the line containing `byte` begins (ignoring leading whitespace)
/// with `#`.
fn line_is_preprocessor_directive(source: &str, byte: usize) -> bool {
    let line_start = source[..byte].rfind('\n').map_or(0, |i| i + 1);
    source[line_start..].trim_start().starts_with('#')
}

/// Number of `ERROR` and `MISSING` nodes in the tree -- the comparison used
/// to decide between two candidate repairs of the same defect.
fn error_node_count(node: &Node) -> usize {
    query::find_descendants(*node, |n| n.is_error() || n.is_missing()).len()
}

/// The byte range of every macro invocation `NAME(...)` whose parentheses
/// hold the keyword `return`, which the parser stranded as an identifier
/// inside an `ERROR` node.
///
/// No C expression or declarator can contain `return` between parentheses:
/// it begins a statement, and a statement in parentheses needs braces
/// (`({ ... })`). So such an invocation is a macro whose argument is not C,
/// the way an annotation language writes a postcondition: the Windows
/// SDK's `_Success_(return == 0)` and `_When_(return != 0, ...)`, defined in
/// a header no single-file parse sees. Placement decides how far the damage
/// spreads. After another annotation (`_Check_return_wat_ _Success_(return
/// == 0) errno_t fopen_s(...);`), tree-sitter reads the invocation as the
/// declarator of a function named `_Success_` and the real prototype as a
/// call inside it, so the header declares `_Success_` and not `fopen_s`.
/// The invocation was already unusable to every rule, so blanking it loses
/// nothing and lets the declaration after it parse.
///
/// Keyed on the keyword, never on the macro's name. The enclosing `(` is
/// found in the source with literals and comments masked
/// (`pp_tokens::mask_source`). The search gives up at a `{`, `}` or `;`,
/// which no single macro argument holds, so a real `return` statement is
/// never mistaken for an argument. A `return` on a directive line is left
/// alone, and so is one inside a keyword's parentheses (`if (... return`)
/// or anywhere in a function body: an annotation sits on a declaration,
/// and a body the parser damaged (an `if (` split across `#if` arms) can
/// strand a real `return` beside an unclosed `(`.
///
/// An invocation that a `;` ends is a statement, not an annotation: a
/// macro that takes a statement as its argument and expands it or not by
/// configuration (`FAULT_INJECT(return ERR_IO);`). It is left alone, so the
/// blank does not leave a lone `;` in a body for a rule to read as an empty
/// statement. An annotation is followed by what it annotates.
fn find_keyword_argument_macro_invocations(node: &Node, source: &str) -> Vec<(usize, usize)> {
    let stranded = query::find_descendants(*node, |n| {
        matches!(n.kind(), "identifier" | "type_identifier")
            && &source[n.start_byte()..n.end_byte()] == "return"
            && query::nearest_ancestor_of_kind(n, "ERROR").is_some()
            && query::nearest_ancestor_of_kind(n, "compound_statement").is_none()
    });
    if stranded.is_empty() {
        return Vec::new();
    }
    let masked = crate::utility::cert_c::pp_tokens::mask_source(source);
    let bytes = masked.as_bytes();
    let mut ranges: Vec<(usize, usize)> = stranded
        .iter()
        .filter(|n| !line_is_preprocessor_directive(source, n.start_byte()))
        .filter_map(|n| outermost_annotation(bytes, n.start_byte()))
        .filter(|&(_, end)| next_non_space(bytes, end) != Some(b';'))
        .collect();
    ranges.sort_unstable();
    ranges.dedup();
    // Two `return`s in one annotation (`_When_(return != 0, _Post_(return
    // > 1))`) yield overlapping ranges; keep the first, which encloses.
    let mut outermost: Vec<(usize, usize)> = Vec::new();
    for range in ranges {
        match outermost.last() {
            Some(&(_, end)) if range.0 < end => {}
            _ => outermost.push(range),
        }
    }
    outermost
}

/// The byte range of every macro invocation that trails a function's
/// parameter list, `MACRO(args)` in `void f(const char *fmt, ...)
/// PRINTF_LIKE(1, 2);`, in a top-level item the parser damaged.
///
/// tree-sitter-c reads such an invocation as a `call_expression` inside the
/// `function_declarator`, after its parameters. After preprocessing no
/// declarator ends in a call: `f(...)(...)` declares a function returning a
/// function, which C forbids, so the invocation is always a macro that
/// expands to an attribute or to nothing. Where it stands decides how much
/// it costs. Followed by a prototype that itself begins with an annotation
/// macro (dbus writes every prototype as `EXPORT_MACRO` / `void name(...)
/// FORMAT_MACRO(3, 4);`), the parser reads the `;` and the next prototype's
/// type and name into an `ERROR` inside the first declaration, and one of
/// the two prototypes is lost to every rule. Blanking the invocation leaves
/// both prototypes whole.
///
/// Keyed on the parser's own placement of the invocation, never on its
/// name, and on what a declarator's attributes are followed by: the `;` of a
/// prototype, the `{` of a definition, or the `,` before another declarator.
/// Statement macros in a body the parser lost (`C2S(CMD_1)` / `C2S(CMD_2)`,
/// each expanding to a `case` label) can be read as the same trailing
/// calls on a declarator that does not exist; they run on to the next
/// statement or the `}` of the block instead, so they are left as written.
/// Only an invocation in a top-level item that holds an `ERROR` or `MISSING`
/// node is taken: in an item that parses cleanly it does no harm, and the
/// repair touches nothing it does not need to.
fn find_trailing_attribute_invocations(node: &Node, source: &str) -> Vec<(usize, usize)> {
    let candidates = query::find_descendants(*node, |n| {
        n.kind() == "call_expression"
            && n.parent()
                .is_some_and(|p| p.kind() == "function_declarator")
            && n.child_by_field_name("function")
                .is_some_and(|f| f.kind() == "identifier")
            && top_level_item(&n).has_error()
            && !line_is_preprocessor_directive(source, n.start_byte())
    });
    if candidates.is_empty() {
        return Vec::new();
    }
    let masked = crate::utility::cert_c::pp_tokens::mask_source(source);
    candidates
        .iter()
        .filter(|n| {
            n.parent()
                .is_some_and(|d| ends_in_attributes_only(&d, &masked))
        })
        .map(|n| (n.start_byte(), n.end_byte()))
        .collect()
}

/// Whether everything in `declarator` after its parameter list is attribute
/// invocations, and the declarator is followed by what ends one: `;`, `{` or
/// `,`. Nothing but the invocations themselves may stand between: no `{`,
/// `}` or `;` in `masked` (the source with comments and literal contents
/// blanked), and every child after the parameters is a call with no `ERROR`
/// or `MISSING` node anywhere inside it. A declarator the parser assembled
/// out of a lost function body spans a `}` or an `ERROR` on its way to
/// whatever follows it, and one assembled out of a body macro and the next
/// prototype (`int get(int a) BODY(a)` / `int helper(int b);`) holds that
/// prototype's type as a bare identifier and its name and parameters as a
/// call whose argument list hides the `ERROR`.
fn ends_in_attributes_only(declarator: &Node, masked: &str) -> bool {
    let Some(params) = declarator.child_by_field_name("parameters") else {
        return false;
    };
    let tail = &masked[params.end_byte()..declarator.end_byte()];
    let mut cursor = declarator.walk();
    let tail_is_attributes = !tail.contains(['{', '}', ';'])
        && declarator
            .children(&mut cursor)
            .filter(|c| c.start_byte() >= params.end_byte())
            .all(|c| c.kind() == "call_expression" && !c.has_error());
    tail_is_attributes
        && matches!(
            next_non_space(masked.as_bytes(), declarator.end_byte()),
            Some(b';' | b'{' | b',')
        )
}

/// The ancestor of `node` that is a direct child of the root, or the root
/// itself for a node with no such ancestor.
fn top_level_item<'a>(node: &Node<'a>) -> Node<'a> {
    let mut item = *node;
    while let Some(parent) = item.parent() {
        if parent.parent().is_none() {
            return item;
        }
        item = parent;
    }
    item
}

/// The invocation around the byte at `at` (see [`enclosing_invocation`]),
/// widened to each invocation it is a whole argument of.
/// `_When_(x > 0, _Success_(return != 0)) int h(int x);` blanks all of
/// `_When_(...)`: the inner `_Success_(...)` alone leaves `_When_(x > 0, )`
/// to misparse as the declarator. A whole argument is preceded by `(` or
/// `,` and followed by `,` or `)`. A parameter's annotation is not: one
/// before the parameter is followed by its type (`int fill(OUT_TO(n,
/// return) char *buf, int n) __attribute__((nonnull));`), and one after
/// is preceded by its name (`int q(int n, char *buf OUT_TO(n, return))
/// NOTHROW;`). So the widening never takes the parameter list around it,
/// whatever follows the list. The widening also stops when no name follows
/// the outer invocation; no known shape reaches that stop, and it is kept
/// as a defensive guard.
fn outermost_annotation(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut range = enclosing_invocation(bytes, at)?;
    while let Some(outer) = enclosing_invocation(bytes, range.0) {
        let is_argument = matches!(prev_non_space(bytes, range.0), Some(b'(' | b','))
            && matches!(next_non_space(bytes, range.1), Some(b',' | b')'));
        if !is_argument {
            break;
        }
        let followed_by_name =
            next_non_space(bytes, outer.1).is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
        if !followed_by_name {
            break;
        }
        range = outer;
    }
    Some(range)
}

/// The last byte before `at` that is not whitespace.
fn prev_non_space(bytes: &[u8], at: usize) -> Option<u8> {
    bytes[..at]
        .iter()
        .rev()
        .copied()
        .find(|b| !b.is_ascii_whitespace())
}

/// The first byte at or after `at` that is not whitespace.
fn next_non_space(bytes: &[u8], at: usize) -> Option<u8> {
    bytes[at..]
        .iter()
        .copied()
        .find(|b| !b.is_ascii_whitespace())
}

/// The range of `NAME(...)` around the byte at `at` in masked source: the
/// nearest unclosed `(` before it, the identifier right before that, and
/// the `)` that closes it. `None` at a `{`, `}` or `;` first, at a keyword
/// before the `(`, or when the `)` never comes.
fn enclosing_invocation(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut depth = 0usize;
    let mut open = None;
    for i in (0..at).rev() {
        match bytes[i] {
            b')' => depth += 1,
            b'(' if depth == 0 => {
                open = Some(i);
                break;
            }
            b'(' => depth -= 1,
            b'{' | b'}' | b';' => return None,
            _ => {}
        }
    }
    let open = open?;
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut name_end = open;
    while name_end > 0 && bytes[name_end - 1].is_ascii_whitespace() {
        name_end -= 1;
    }
    let mut name_start = name_end;
    while name_start > 0 && is_ident(bytes[name_start - 1]) {
        name_start -= 1;
    }
    let name = std::str::from_utf8(&bytes[name_start..name_end]).ok()?;
    if !is_bare_identifier(name) {
        return None;
    }
    depth = 0;
    for (i, &b) in bytes.iter().enumerate().skip(open + 1) {
        match b {
            b'(' => depth += 1,
            b')' if depth == 0 => return Some((name_start, i + 1)),
            b')' => depth -= 1,
            b'{' | b'}' | b';' => return None,
            _ => {}
        }
    }
    None
}

/// Depth-first search for a `preproc_if`/`preproc_ifdef`/`preproc_elif`-style
/// conditional node whose entire guarded content is a single ERROR-wrapped
/// bare brace (`{` or `}`). This is the dual-C/C++-header idiom for
/// conditionally opening/closing an `extern "C"` block:
/// ```c
/// #if defined(__cplusplus)
/// extern "C" {
/// #endif
/// ...
/// #if defined(__cplusplus)
/// }
/// #endif
/// ```
/// tree-sitter-c's grammar doesn't accept a lone `}` (or `{`) as valid
/// preproc-conditional content in this position -- confirmed on raylib's
/// rlgl.h: the resulting ERROR, though itself small and locally
/// contained, made the GLR parser's global cost-based recovery flatten the
/// ENTIRE enclosing `#ifndef` header guard (differently-parsed and clean in
/// isolation) into one giant ERROR node spanning almost the whole file.
///
/// Unlike [`find_blankable_identifier_error`], this never removes the brace
/// itself (real, structurally load-bearing code) -- only the surrounding
/// `#if`/`#ifdef`/`#elif`-style condition line and its matching `#endif`
/// token, which is what the grammar can't place, are blanked. Returns the
/// two byte ranges to blank.
///
/// Requires the ERROR-brace to be the ONLY named child between the
/// condition and `#endif` (comments aside) -- i.e. that this conditional's
/// entire guarded content really is just the lone brace, per the doc
/// comment above. An earlier fix found a false match on mosquitto's uthash.h:
/// a switch/case-in-macro construct elsewhere in the file cascades into
/// several small, unrelated single-token `{`/`}` ERROR nodes scattered as
/// *direct children of the file's own top-level `#ifndef UTHASH_H` header
/// guard* (which spans nearly the whole file and has hundreds of other,
/// legitimate children in between). The old code took the *first* such
/// ERROR child and paired it with the node's `#endif` child regardless of
/// what stood between them -- for a whole-file header guard that `#endif`
/// is always the real, load-bearing file-closing guard, so this blanked
/// away the file's genuine closing `#endif` line while leaving hundreds of
/// lines of real code in between (a large corruption of unrelated,
/// correctly-parsed content, not the narrow single-line-pair blank the
/// function is meant to make).
fn find_blankable_preproc_brace_error(
    node: &Node,
    source: &str,
) -> Option<((usize, usize), (usize, usize))> {
    let conditionals = query::find_descendants_of_kinds(
        *node,
        &[
            "preproc_if",
            "preproc_ifdef",
            "preproc_elif",
            "preproc_elifdef",
        ],
    );
    conditionals
        .into_iter()
        .find_map(|node| lone_brace_guard_ranges(&node, source))
}

/// The two ranges [`find_blankable_preproc_brace_error`] blanks when this
/// one conditional's guarded content is a lone ERROR-wrapped brace.
fn lone_brace_guard_ranges(node: &Node, source: &str) -> Option<((usize, usize), (usize, usize))> {
    {
        let mut cursor = node.walk();
        let children: Vec<Node> = node.children(&mut cursor).collect();
        if let Some(endif_idx) = children
            .iter()
            .position(|c| !c.is_named() && c.kind() == "#endif")
        {
            // Walk backward from #endif, skipping only comments. The very
            // next non-comment child must be the lone brace ERROR node --
            // anything else (another ERROR, a statement, a declaration...)
            // means this conditional's guarded content is not just the
            // brace, so it isn't the idiom this function targets.
            let mut idx = endif_idx;
            let mut error_child = None;
            while idx > 0 {
                idx -= 1;
                let c = &children[idx];
                if c.kind() == "comment" {
                    continue;
                }
                if c.is_error() {
                    let trimmed = source[c.start_byte()..c.end_byte()].trim();
                    if trimmed == "{" || trimmed == "}" {
                        error_child = Some(*c);
                    }
                }
                break;
            }
            if let Some(err) = error_child {
                return Some((
                    (node.start_byte(), err.start_byte()),
                    (
                        children[endif_idx].start_byte(),
                        children[endif_idx].end_byte(),
                    ),
                ));
            }
        }
    }
    None
}

/// Parse `source`, then iteratively blank and re-parse away any single-token
/// unknown-identifier `ERROR` node found, up to `MAX_ITERATIONS` times.
/// Returns the final tree and the (possibly blanked) source text paired with
/// it -- callers should use the returned text as "source" everywhere
/// downstream, exactly as with `empty_macro_blank`. `None` only if
/// tree-sitter itself fails to produce a tree at all (e.g. parser
/// misconfiguration), matching `Parser::parse`'s own `Option` contract --
/// this never panics.
pub fn parse_with_recovery(
    parser: &mut Parser,
    source: String,
    macros: &RepairMacros,
) -> Option<(Tree, String)> {
    let mut text = source;
    let mut tree = parser.parse(&text, None)?;

    for _ in 0..MAX_ITERATIONS {
        crate::analyze::containment::checkpoint();
        if !tree.root_node().has_error() {
            break;
        }
        // First, and all at once: each is certain on its own, and blanking
        // one per pass would spend the iteration budget on a header that
        // annotates every prototype.
        let invocations = find_keyword_argument_macro_invocations(&tree.root_node(), &text);
        if !invocations.is_empty() {
            for (start, end) in invocations {
                text = blank_range(&text, start, end);
            }
        } else if let Some(repaired) = blank_if_fewer_errors(
            parser,
            &text,
            &tree,
            &find_trailing_attribute_invocations(&tree.root_node(), &text),
        ) {
            (text, tree) = repaired;
            continue;
        } else if let Some(repaired) =
            repair_annotations_taken_for_type(parser, &text, &tree, macros)
        {
            (text, tree) = repaired;
            continue;
        } else if let Some((start, end)) = find_blankable_identifier_error(&tree.root_node(), &text)
        {
            let (repaired, repaired_tree) = choose_repair(parser, &text, start, end, macros)?;
            text = repaired;
            tree = repaired_tree;
            continue;
        } else if let Some(((s1, e1), (s2, e2))) =
            find_blankable_preproc_brace_error(&tree.root_node(), &text)
        {
            text = blank_range(&text, s1, e1);
            text = blank_range(&text, s2, e2);
        } else {
            break;
        }
        tree = parser.parse(&text, None)?;
    }

    Some((tree, text))
}

/// Whether a definition the file writes for an annotation candidate leaves
/// it safe to blank: an object-like macro whose replacement holds no C
/// keyword (a storage class, `inline`, a type, `_Noreturn`) and no noreturn
/// spelling -- nothing, an `__attribute__((...))`, a vendor annotation or
/// another macro's name. A function-like or unreadable one is not.
fn is_annotation_definition(definition: &crate::analyze::check_macros::MacroDefinition) -> bool {
    let crate::analyze::check_macros::MacroDefinition::Object { body } = definition else {
        return false;
    };
    !body.contains("noreturn")
        && !body
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|token| is_c_keyword(token) || NON_TYPE_SPECIFIER_KEYWORDS.contains(&token))
}

/// Blank every [`find_annotation_taken_for_type`] at once and re-parse, except
/// a name whose definition carries meaning a rule reads by name
/// ([`RepairMacros::meaningful_macros`], or a definition in this file
/// [`is_annotation_definition`] refuses); the repair stands only when the re-parse has fewer `ERROR`/`MISSING` nodes.
/// `None` when there is none, or the repair does not help -- the stranded
/// keyword then stays, as it always did.
fn repair_annotations_taken_for_type(
    parser: &mut Parser,
    source: &str,
    tree: &Tree,
    macros: &RepairMacros,
) -> Option<(String, Tree)> {
    let mut sites = find_annotation_taken_for_type(&tree.root_node(), source);
    if sites.is_empty() {
        return None;
    }
    let own = crate::analyze::check_macros::collect_macro_definitions(source);
    sites.retain(|&(start, end)| {
        let name = &source[start..end];
        !macros.meaningful_macros.contains(name)
            && own
                .get(name)
                .is_none_or(|defs| defs.iter().all(is_annotation_definition))
    });
    blank_if_fewer_errors(parser, source, tree, &sites)
}

/// Blank every range in `sites` at once and re-parse. The result stands only
/// when the re-parse has fewer `ERROR`/`MISSING` nodes than `tree`; `None`
/// when `sites` is empty or the blank does not help.
fn blank_if_fewer_errors(
    parser: &mut Parser,
    source: &str,
    tree: &Tree,
    sites: &[(usize, usize)],
) -> Option<(String, Tree)> {
    if sites.is_empty() {
        return None;
    }
    let mut text = source.to_string();
    for &(start, end) in sites {
        text = blank_range(&text, start, end);
    }
    let repaired = parser.parse(&text, None)?;
    let fewer_errors =
        error_node_count(&repaired.root_node()) < error_node_count(&tree.root_node());
    let after = settled_function_declarators(&repaired.root_node(), &text);
    let keeps_every_declaration = settled_function_declarators(&tree.root_node(), source)
        .iter()
        .all(|(name, count)| after.get(name).is_some_and(|kept| kept >= count));
    (fewer_errors && keeps_every_declaration).then_some((text, repaired))
}

/// How many times each function name is declared or defined in `root` by a
/// settled `function_declarator`: one with no `ERROR` ancestor, which the
/// parser fully placed. The name is the declarator's innermost identifier.
///
/// [`blank_if_fewer_errors`] accepts a repair only when no name has fewer
/// settled declarators after it than before. A lower `ERROR` count alone is
/// not enough: a repair can tidy two errors away while the parser folds the
/// next prototype into the one before it, and that prototype is then lost
/// to every rule. Counting rather than collecting names catches a function
/// that is both prototyped and defined and loses one of the two, and
/// counting only settled declarators on both sides catches one the repair
/// moved under an `ERROR`.
fn settled_function_declarators(root: &Node, source: &str) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    let names = query::find_descendants(*root, |n| {
        n.kind() == "function_declarator" && query::nearest_ancestor_of_kind(n, "ERROR").is_none()
    })
    .into_iter()
    .filter_map(|declarator| {
        let mut inner = declarator.child_by_field_name("declarator")?;
        for _ in 0..MAX_DECLARATOR_DEPTH {
            if inner.kind() == "identifier" {
                return Some(source[inner.start_byte()..inner.end_byte()].to_string());
            }
            inner = inner
                .child_by_field_name("declarator")
                .or_else(|| inner.named_child(0))?;
        }
        None
    });
    for name in names {
        *counts.entry(name).or_insert(0) += 1;
    }
    counts
}

/// How deep [`settled_function_declarators`] follows nested declarators
/// (pointer, parenthesized, function) to a function's name.
const MAX_DECLARATOR_DEPTH: usize = 8;

/// Repair the defect tree-sitter reported by stranding `source[start..end]`,
/// returning the repaired text and its re-parse.
///
/// Two candidates: blank the stranded token (what this pass has always
/// done), or -- when the stranded token is not itself a known macro and the
/// token right before it is one -- blank that macro instead, leaving the
/// stranded token, which is real code, in place. The macro candidate is
/// taken whenever its re-parse is no *worse* than the stranded one's, ties
/// included: an equally clean parse that keeps the declaration's real type
/// and name is strictly better for every rule downstream, and the macro is
/// the token that provably cannot appear in preprocessed source anyway.
fn choose_repair(
    parser: &mut Parser,
    source: &str,
    start: usize,
    end: usize,
    macros: &RepairMacros,
) -> Option<(String, Tree)> {
    let stranded_text = blank_or_mark(source, start, end, macros);
    let stranded_tree = parser.parse(&stranded_text, None)?;

    if !macros.object_macros.contains(&source[start..end]) {
        let stranded_errors = error_node_count(&stranded_tree.root_node());
        for (macro_start, macro_end) in preceding_macro_tokens(source, start, macros) {
            let macro_text = blank_or_mark(source, macro_start, macro_end, macros);
            if let Some(macro_tree) = parser.parse(&macro_text, None) {
                if error_node_count(&macro_tree.root_node()) <= stranded_errors {
                    return Some((macro_text, macro_tree));
                }
            }
        }
    }

    Some((stranded_text, stranded_tree))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::c_language;

    fn recover(src: &str) -> (bool, String) {
        recover_with(src, &RepairMacros::default())
    }

    /// As [`recover`], but with a prescan macro table in play.
    fn recover_with(src: &str, macros: &RepairMacros) -> (bool, String) {
        let mut parser = Parser::new();
        parser.set_language(&c_language()).unwrap();
        let (tree, text) = parse_with_recovery(&mut parser, src.to_string(), macros).unwrap();
        (tree.root_node().has_error(), text)
    }

    fn macros(object: &[&str], unused_attr: &[&str]) -> RepairMacros {
        RepairMacros {
            object_macros: object.iter().map(|s| (*s).to_string()).collect(),
            unused_attribute_macros: unused_attr.iter().map(|s| (*s).to_string()).collect(),
            storage_class_macros: Arc::default(),
            include_edges: Arc::default(),
            meaningful_macros: HashSet::new(),
        }
    }

    /// An annotation macro the parser took for the type: every shape whose
    /// real type it stranded gets that type back, and the macro is blanked
    /// in place, whatever it is called and with no prescan.
    #[test]
    fn blanks_an_annotation_taken_for_a_declarations_type() {
        for (src, kept) in [
            ("CHECKED\nstatic int f(void) { return 0; }\n", "static int f(void)"),
            ("CHECKED\nint f(void) { return 0; }\n", "int f(void)"),
            ("CHECKED\nstatic inline int f(void) { return 0; }\n", "static inline int f"),
            ("CHECKED\nstatic unsigned char *g(void);\n", "static unsigned char *g(void);"),
            ("CHECKED\nstatic const char *h(void);\n", "static const char *h(void);"),
            ("CHECKED\nstatic struct s *k(void);\n", "static struct s *k(void);"),
            (
                "#if defined(A) || \\\n    defined(B)\nCHECKED\nstatic int f(void) { return 0; }\n#endif\n",
                "static int f(void)",
            ),
            (
                "/* doc */ CHECKED\nstatic int f(void) { return 0; }\n",
                "static int f(void)",
            ),
        ] {
            let (has_error, text) = recover(src);
            assert!(!has_error, "{src:?} -> {text:?}");
            assert_eq!(text.len(), src.len());
            assert!(!text.contains("CHECKED"), "{text:?}");
            assert!(text.contains(kept), "{text:?}");
        }
    }

    /// A name whose definition means something the rules read by name is
    /// never blanked: one the file defines as a storage class, `static
    /// inline`, a type or a noreturn spelling, or one the project marks as
    /// such. An attribute the file defines, or none, is.
    #[test]
    fn keeps_an_annotation_whose_definition_carries_meaning() {
        for def in [
            "#define LOCAL static inline\n",
            "#define LOCAL static\n",
            "#define LOCAL __attribute__((__noreturn__))\n",
            "#define LOCAL [[noreturn]]\n",
            "#define LOCAL(x) x\n",
        ] {
            let src = format!("{def}LOCAL\nint f(void) {{ return 0; }}\n");
            let (_, text) = recover(&src);
            assert!(text.contains("LOCAL\nint f"), "{def:?} -> {text:?}");
        }
        let src = "LOCAL\nint f(void) { return 0; }\n";
        let mut marked = macros(&["LOCAL"], &[]);
        marked.meaningful_macros.insert("LOCAL".to_string());
        let (_, text) = recover_with(src, &marked);
        assert!(text.contains("LOCAL\nint f"), "{text:?}");
        let src = "#define CHECKED __attribute__((__warn_unused_result__))\nCHECKED\nint f(void) { return 0; }\n";
        let (has_error, text) = recover(src);
        assert!(!has_error, "{text:?}");
        assert!(!text.contains("CHECKED\nint f"), "{text:?}");
    }

    /// A macro invocation trailing a prototype's parameter list, followed by
    /// a prototype that begins with an annotation macro: both prototypes
    /// come out whole, whatever the macros are called.
    #[test]
    fn blanks_a_macro_invocation_trailing_a_prototype() {
        let src = "EXPORTED\nvoid set_error(int *e, const char *fmt, ...) PRINTF_LIKE (2, 3);\n\
                   EXPORTED\nvoid set_error_const(int *e, const char *msg);\n";
        let (has_error, text) = recover(src);
        assert!(!has_error, "{text:?}");
        assert!(!text.contains("PRINTF_LIKE"), "{text:?}");
        assert!(
            text.contains("void set_error(int *e, const char *fmt, ...)"),
            "{text:?}"
        );
        assert!(
            text.contains("void set_error_const(int *e, const char *msg);"),
            "{text:?}"
        );
        assert_eq!(src.len(), text.len());
        assert_eq!(src.lines().count(), text.lines().count());

        let src = "void f(int a) M(3, 4);\nvoid g(int b);\n";
        let (has_error, text) = recover(src);
        assert!(!has_error, "{text:?}");
        assert_eq!(text, src.replace("M(3, 4)", "       "), "{text:?}");
    }

    /// A blank that lowers the `ERROR` count is still refused when a
    /// function the parser had fully placed is no longer declared after it.
    /// Blanking only the export macros here lets the parser fold the second
    /// prototype into the first, around the trailing macro left in place.
    #[test]
    fn refuses_a_blank_that_loses_a_settled_declaration() {
        let src = concat!(
            "typedef struct ErrorState ErrorState;\n",
            "EXPORTED\n",
            "void        lib_error_free      (ErrorState       *error);\n",
            "EXPORTED\n",
            "void        lib_set_error       (ErrorState       *error,\n",
            "                                  const char      *name,\n",
            "                                  const char      *message,\n",
            "                                  ...) PRINTF_LIKE (3, 4);\n",
            "EXPORTED\n",
            "void        lib_set_error_const (ErrorState       *error,\n",
            "                                  const char      *name,\n",
            "                                  const char      *message);\n",
            "EXPORTED\n",
            "void        lib_move_error      (ErrorState       *src,\n",
            "                                  ErrorState       *dest);\n",
        );
        let mut parser = Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let settled = settled_function_declarators(&tree.root_node(), src);
        assert!(settled.contains_key("lib_set_error_const"), "{settled:?}");
        let exports: Vec<(usize, usize)> = src
            .match_indices("EXPORTED")
            .map(|(i, m)| (i, i + m.len()))
            .collect();
        let blanked = exports
            .iter()
            .fold(src.to_string(), |text, &(s, e)| blank_range(&text, s, e));
        let blanked_tree = parser.parse(&blanked, None).unwrap();
        assert!(
            error_node_count(&blanked_tree.root_node()) < error_node_count(&tree.root_node()),
            "the blank alone looks like an improvement"
        );
        assert!(
            !settled_function_declarators(&blanked_tree.root_node(), &blanked)
                .contains_key("lib_set_error_const"),
            "and loses a prototype"
        );
        assert!(blank_if_fewer_errors(&mut parser, src, &tree, &exports).is_none());
    }

    /// The same blank is refused when the lost prototype's function is also
    /// defined further down: the definition survives, but one of the name's
    /// two declarators does not, and the guard counts them.
    #[test]
    fn refuses_a_blank_that_loses_a_prototype_of_a_defined_function() {
        let src = concat!(
            "typedef struct ErrorState ErrorState;\n",
            "EXPORTED\n",
            "void        lib_error_free      (ErrorState       *error);\n",
            "EXPORTED\n",
            "void        lib_set_error       (ErrorState       *error,\n",
            "                                  const char      *name,\n",
            "                                  const char      *message,\n",
            "                                  ...) PRINTF_LIKE (3, 4);\n",
            "EXPORTED\n",
            "void        lib_set_error_const (ErrorState       *error,\n",
            "                                  const char      *name,\n",
            "                                  const char      *message);\n",
            "EXPORTED\n",
            "void        lib_move_error      (ErrorState       *src,\n",
            "                                  ErrorState       *dest);\n",
            "void lib_set_error_const(ErrorState *error, const char *name, const char *message)\n",
            "{\n",
            "}\n",
        );
        let mut parser = Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let before = settled_function_declarators(&tree.root_node(), src);
        assert_eq!(before.get("lib_set_error_const"), Some(&2), "{before:?}");
        let exports: Vec<(usize, usize)> = src
            .match_indices("EXPORTED")
            .map(|(i, m)| (i, i + m.len()))
            .collect();
        let blanked = exports
            .iter()
            .fold(src.to_string(), |text, &(s, e)| blank_range(&text, s, e));
        let blanked_tree = parser.parse(&blanked, None).unwrap();
        let after = settled_function_declarators(&blanked_tree.root_node(), &blanked);
        assert_eq!(after.get("lib_set_error_const"), Some(&1), "{after:?}");
        assert!(blank_if_fewer_errors(&mut parser, src, &tree, &exports).is_none());
    }

    /// A function-like macro that expands to a definition's body, followed
    /// by a prototype: the parser reads the macro, the next prototype's type
    /// and its name and parameters as calls trailing the first declarator,
    /// with the `ERROR` inside the last call's arguments. None of it is an
    /// attribute run, and the trailing repair blanks nothing. (The
    /// single-identifier repair still blanks the parameter name `b`, as it
    /// always has; `helper` keeps its name and its prototype.)
    #[test]
    fn leaves_a_body_macro_and_the_next_prototype_alone() {
        let src = concat!(
            "#define GETTER(n) { return n; }\n",
            "int get_a(int a) GETTER(a)\n",
            "int helper(int b);\n",
            "int k(void) { return helper(2); }\n",
        );
        let (_, text) = recover(src);
        assert!(text.contains("int get_a(int a) GETTER(a)\n"), "{text:?}");
        assert!(text.contains("\nint helper(int "), "{text:?}");
        assert!(
            text.ends_with(");\nint k(void) { return helper(2); }\n"),
            "{text:?}"
        );
        let mut parser = Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        assert!(find_trailing_attribute_invocations(&tree.root_node(), src).is_empty());
    }

    /// An invocation trailing a prototype in an item that parses cleanly is
    /// left as written, even while another item in the file is repaired.
    #[test]
    fn leaves_a_trailing_invocation_in_a_clean_item_alone() {
        let src = "int *f(int a) M(1);\nCHECKED\nstatic int g(void) { return 0; }\n";
        let (has_error, text) = recover(src);
        assert!(!has_error, "{text:?}");
        assert!(text.contains("int *f(int a) M(1);"), "{text:?}");
    }

    /// Every such site is repaired in one pass, not one per iteration: a file
    /// with more of them than the iteration budget still parses clean.
    #[test]
    fn blanks_every_annotation_taken_for_a_type_at_once() {
        let src: String = (0..20)
            .map(|i| format!("CHECKED\nstatic int f{i}(void) {{ return {i}; }}\n"))
            .collect();
        let (has_error, text) = recover(&src);
        assert!(!has_error);
        assert!(!text.contains("CHECKED"));
    }

    /// A type name before a storage class is valid C and parses clean, so
    /// nothing is blanked; and an identifier that does not begin the
    /// declaration (the tail of an expression) is not taken for one.
    #[test]
    fn leaves_a_type_before_its_storage_class_and_a_non_leading_name_alone() {
        let src = "typedef int myint;\nmyint static f(void) { return 0; }\n";
        let (has_error, text) = recover(src);
        assert!(!has_error);
        assert_eq!(text, src);
        let bytes = "int x = a + b\nstatic int f(void);\n";
        let mut parser = Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(bytes, None).unwrap();
        assert!(find_annotation_taken_for_type(&tree.root_node(), bytes).is_empty());
    }

    #[test]
    fn recovers_unknown_calling_convention_in_funcptr_typedef() {
        // GL_APIENTRYP has no local #define anywhere in this snippet --
        // an earlier fix's fix has nothing to find here.
        let src = "typedef void (GL_APIENTRYP PFNGLFOO)(int x);\nint y = 1;\n";
        let (has_error, _) = recover(src);
        assert!(!has_error);
    }

    #[test]
    fn preserves_byte_length() {
        let src = "typedef void (GL_APIENTRYP PFNGLFOO)(int x);\nint y = 1;\n";
        let (_, text) = recover(src);
        assert_eq!(text.len(), src.len());
        let pos_orig = src.find("int y = 1;").unwrap();
        let pos_out = text.find("int y = 1;").unwrap();
        assert_eq!(pos_orig, pos_out);
    }

    #[test]
    fn clean_file_untouched_and_no_reparse_cost() {
        let src = "int main(void) { return 0; }\n";
        let (has_error, text) = recover(src);
        assert!(!has_error);
        assert_eq!(text, src);
    }

    #[test]
    fn blanks_an_annotation_whose_argument_names_return() {
        let src = "CHECKED\nON_SUCCESS(return == 0)\nint open_it(int **out);\n";
        let (_, text) = recover(src);
        assert_eq!(text.len(), src.len());
        assert!(!text.contains("ON_SUCCESS"));
        assert!(text.contains("int open_it(int **out);"));
        let mut parser = Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(&text, None).unwrap();
        let declarators = query::find_descendants_of_kind(tree.root_node(), "function_declarator");
        assert_eq!(declarators.len(), 1);
        assert!(text[declarators[0].byte_range()].starts_with("open_it"));
    }

    #[test]
    fn blanks_the_outer_annotation_when_return_is_nested() {
        let src = "CHECKED\nWHEN(return != 0, POST(return > 1))\nint f(int x);\n";
        let (_, text) = recover(src);
        assert!(!text.contains("WHEN") && !text.contains("POST"));
        assert!(text.contains("int f(int x);"));
    }

    #[test]
    fn blanks_the_annotation_around_one_whose_argument_names_return() {
        let src = "CHECKED\nWHEN(x > 0, ON_SUCCESS(return != 0)) EXPORTED int CC h(int x);\n";
        let (_, text) = recover(src);
        assert!(!text.contains("WHEN") && !text.contains("ON_SUCCESS"));
        assert!(text.contains("h(int x);"));
    }

    #[test]
    fn keeps_a_prototype_whose_parameter_annotation_names_return() {
        for trailer in ["", " __attribute__((nonnull))", " ASM_NAME(\"fill2\")"] {
            let src = format!("CHECKED\nint fill(OUT_TO(n, return) char *buf, int n){trailer};\n");
            let (_, text) = recover(&src);
            assert!(!text.contains("OUT_TO"), "{text:?}");
            assert!(text.contains("int fill("), "{text:?}");
            assert!(text.contains("char *buf, int n)"), "{text:?}");
        }
    }

    #[test]
    fn keeps_a_prototype_whose_parameter_annotation_follows_its_name() {
        let src = "CHECKED\nint q(int n, char *buf OUT_TO(n, return)) NOTHROW;\n";
        let (_, text) = recover(src);
        assert!(!text.contains("OUT_TO"), "{text:?}");
        assert!(text.contains("int q(int n, char *buf"), "{text:?}");
    }

    #[test]
    fn leaves_a_real_return_statement_alone() {
        // A `return` the parser cannot place inside a damaged body is not
        // in any macro's parentheses: the search stops at the `;` or `{`.
        let src = "int g(int x) {\n    LOOP(x) return (x);\n}\n";
        let (_, text) = recover(src);
        assert!(text.contains("return (x);"));
        let src = "#define RET(x) (return x)\nint h(void);\n";
        let (_, text) = recover(src);
        assert!(text.starts_with("#define RET(x) (return x)"));
    }

    #[test]
    fn leaves_a_statement_macro_whose_argument_is_a_return_alone() {
        let src = "int g(int x) {\n    FAULT_INJECT( return ERR_IO );\n    if (x) {\n        FAULT_INJECT(return ERR_EMPTY);\n    }\n    return x;\n}\n";
        let (_, text) = recover(src);
        // The invocation stays; only its unknown argument name may be blanked.
        assert!(text.contains("FAULT_INJECT(return "));
        assert!(text.contains("FAULT_INJECT( return "));
    }

    #[test]
    fn never_blanks_a_c_keyword_stranded_in_an_error_node() {
        // STATIC is a real (non-empty) macro for "static" -- gets consumed
        // as the declarator's type_identifier, leaving "void" itself
        // stranded as an ERROR-wrapped identifier leaf. Blanking "void" as
        // if it were an unknown macro would discard the function's actual
        // return type. Real regression: this exact pattern is
        // MSC37-C's tests/pass/macro_before_void.c fixture.
        let src = "#define STATIC static\nSTATIC void f(void) {\n}\n";
        let (_, text) = recover(src);
        // "void" must survive untouched, whatever else changed.
        assert!(text.contains("void f(void)"));
    }

    #[test]
    fn blanks_the_macro_not_the_stranded_type_when_the_table_knows_it() {
        // curl's `CURL_EXTERN CURLcode curl_easy_setopt(...)`: tree-sitter
        // takes CURL_EXTERN for the type and strands CURLcode, so blanking
        // the stranded token throws away the real return type and leaves a
        // macro standing in its place.
        let src = "CURL_EXTERN CURLcode curl_easy_setopt(int o);\n";
        let (has_error, text) = recover_with(src, &macros(&["CURL_EXTERN"], &[]));
        assert!(!has_error);
        assert!(
            text.contains("CURLcode curl_easy_setopt"),
            "the declaration's real type must survive: {text:?}"
        );
        assert!(
            !text.contains("CURL_EXTERN"),
            "the macro is what goes: {text:?}"
        );
        assert_eq!(text.len(), src.len());
    }

    #[test]
    fn without_a_macro_table_the_stranded_token_is_still_the_one_blanked() {
        // The prescan itself parses, so it runs with no table -- that path
        // must keep behaving exactly as it did before an earlier fix.
        let src = "CURL_EXTERN CURLcode curl_easy_setopt(int o);\n";
        let (_, text) = recover(src);
        assert!(text.contains("CURL_EXTERN"));
        assert!(!text.contains("CURLcode"));
    }

    #[test]
    fn never_blanks_a_macro_named_on_its_own_define_line() {
        // `X` is by definition in the macro table while its own `#define`
        // is being read; blanking it there would destroy the definition.
        let src = "#define X\nX GLuint counter;\n";
        let (_, text) = recover_with(src, &macros(&["X", "GLuint"], &[]));
        assert!(
            text.contains("#define X"),
            "definition must survive: {text:?}"
        );
    }

    #[test]
    fn leaves_a_marker_where_a_trailing_unused_attribute_macro_was() {
        // seL4's `word_t totalObjectSize UNUSED;` -- the macro is what the
        // parser strands, so blanking it is right, but MSC13-C still has to
        // be able to see that the author annotated the declaration.
        let src =
            "typedef unsigned long word_t;\nvoid f(void) {\n  word_t totalObjectSize UNUSED;\n}\n";
        let (has_error, text) = recover_with(src, &macros(&["UNUSED"], &["UNUSED"]));
        assert!(!has_error);
        assert!(text.contains(UNUSED_ATTRIBUTE_MARKER), "{text:?}");
        assert_eq!(text.len(), src.len());
    }

    #[test]
    fn leaves_a_marker_where_a_leading_unused_attribute_macro_was() {
        // `UNUSED pptr_t vaddr = ...` -- here the macro precedes the type,
        // so the marker lands just before the recovered declaration rather
        // than inside it, and the declared name is finally the real one.
        let src = "typedef unsigned long pptr_t;\nvoid f(void) {\n  UNUSED pptr_t vaddr = 1;\n}\n";
        let (has_error, text) = recover_with(src, &macros(&["UNUSED"], &["UNUSED"]));
        assert!(!has_error);
        assert!(text.contains(UNUSED_ATTRIBUTE_MARKER), "{text:?}");
        assert!(text.contains("pptr_t vaddr = 1;"), "{text:?}");
        assert_eq!(text.len(), src.len());
    }

    #[test]
    fn does_not_blank_a_meaningful_enum_like_macro() {
        // MAX_SIZE resolves fine as an array bound -- no ERROR node
        // touches it, so recovery must leave it untouched.
        let src = "#define MAX_SIZE 32\nint arr[MAX_SIZE];\n";
        let (has_error, text) = recover(src);
        assert!(!has_error);
        assert_eq!(text, src);
    }

    #[test]
    fn recovers_cplusplus_guarded_extern_c_brace() {
        // An earlier fix: raylib rlgl.h's dual-C/C++ extern "C" guard idiom closes
        // the block with `#if defined(__cplusplus) } #endif` -- a lone brace
        // as the guarded content. tree-sitter-c can't place that bare `}`
        // (it isolates it as a leaf ERROR node inside an otherwise-clean
        // `preproc_if`), reproducible minimally as any declaration directly
        // followed by this idiom -- no `extern "C"` wrapper needed to
        // trigger it. On the real file (verified directly against raylib's
        // rlgl.h, not reproducible in a small snippet -- tree-sitter's GLR
        // disambiguation is a *global*, file-size-sensitive cost comparison)
        // this one small, locally contained defect made the parser flatten
        // the entire enclosing `#ifndef` header guard into one
        // file-spanning ERROR node.
        //
        // This snippet's bare `}` has no matching unguarded `{` (that's
        // rlgl.h's `extern "C" {`, elided here), so it stays a genuine,
        // unrelated "unmatched brace" error even after recovery -- what
        // this test asserts is narrower: recovery must find and blank
        // exactly the surrounding `#if`/`#endif` pair (the part tree-sitter
        // can't place), leaving the brace itself untouched.
        let src = "int x;\n#if defined(__cplusplus)\n}\n#endif\n";
        let (_, text) = recover(src);
        assert!(!text.contains("__cplusplus"));
        assert!(text.contains('}'));
    }

    #[test]
    fn does_not_corrupt_whole_file_header_guard_on_switch_in_macro_error() {
        // An earlier fix: minimal reduction of mosquitto's deps/uthash.h. A
        // backslash-continued do/while(0) macro containing a switch/case
        // (HASH_SFH) makes tree-sitter-c's GLR recovery scatter several
        // small, unrelated single-token `{`/`}` ERROR nodes as *direct
        // children of the file's own top-level `#ifndef UTHASH_H` header
        // guard* -- not wrapped in their own `preproc_if`, unlike the
        // an earlier fix extern "C" idiom this recovery targets. The buggy
        // version of `find_blankable_preproc_brace_error` paired the
        // first such stray ERROR with this node's `#endif` child
        // regardless of what stood between them; for a whole-file header
        // guard that `#endif` is always the real, load-bearing
        // file-closing guard, so it blanked away the real `#ifndef`
        // /`#define` guard lines AND the real closing `#endif`, while
        // leaving the entire macro body in between untouched garbage
        // whitespace -- a large corruption of a file that should have
        // been left alone (recovery has nothing legitimate to fix here;
        // this file's only defect is the same switch-in-macro
        // false-ERROR HASH_SFH itself, which recovery doesn't -- and
        // shouldn't -- touch).
        let src = concat!(
            "#ifndef UTHASH_H\n",
            "#define UTHASH_H\n",
            "#define HASH_SFH(key,keylen,hashv)                                               \\\n",
            "do {                                                                             \\\n",
            "  unsigned const char *_sfh_key=(unsigned const char*)(key);                     \\\n",
            "  uint32_t _sfh_tmp, _sfh_len = (uint32_t)keylen;                                \\\n",
            "  unsigned _sfh_rem = _sfh_len & 3U;                                             \\\n",
            "  _sfh_len >>= 2;                                                                \\\n",
            "  hashv = 0xcafebabeu;                                                           \\\n",
            "  for (;_sfh_len > 0U; _sfh_len--) {                                             \\\n",
            "    hashv    += get16bits (_sfh_key);                                            \\\n",
            "    _sfh_tmp  = ((uint32_t)(get16bits (_sfh_key+2)) << 11) ^ hashv;              \\\n",
            "    hashv     = (hashv << 16) ^ _sfh_tmp;                                        \\\n",
            "    _sfh_key += 2U*sizeof (uint16_t);                                            \\\n",
            "    hashv    += hashv >> 11;                                                     \\\n",
            "  }                                                                              \\\n",
            "  switch (_sfh_rem) {                                                            \\\n",
            "    case 3: hashv += get16bits (_sfh_key);                                       \\\n",
            "            hashv ^= hashv << 16;                                                \\\n",
            "            hashv ^= (uint32_t)(_sfh_key[sizeof (uint16_t)]) << 18;              \\\n",
            "            hashv += hashv >> 11;                                                \\\n",
            "            break;                                                               \\\n",
            "    case 2: hashv += get16bits (_sfh_key);                                       \\\n",
            "            hashv ^= hashv << 11;                                                \\\n",
            "            hashv += hashv >> 17;                                                \\\n",
            "            break;                                                               \\\n",
            "    case 1: hashv += *_sfh_key;                                                  \\\n",
            "            hashv ^= hashv << 10;                                                \\\n",
            "            hashv += hashv >> 1;                                                 \\\n",
            "            break;                                                               \\\n",
            "    default: ;                                                                   \\\n",
            "  }                                                                              \\\n",
            "  hashv ^= hashv << 3;                                                           \\\n",
            "  hashv += hashv >> 5;                                                           \\\n",
            "  hashv ^= hashv << 4;                                                           \\\n",
            "  hashv += hashv >> 17;                                                          \\\n",
            "  hashv ^= hashv << 25;                                                          \\\n",
            "  hashv += hashv >> 6;                                                           \\\n",
            "} while (0)\n",
            "int tail;\n",
            "#endif\n",
        );
        let (_, text) = recover(src);
        assert_eq!(text, src, "recovery must not alter this file at all");
    }

    #[test]
    fn preproc_brace_recovery_preserves_byte_length_and_line_count() {
        let src = "int x;\n#if defined(__cplusplus)\n}\n#endif\nint y;\n";
        let (_, text) = recover(src);
        assert_eq!(text.len(), src.len());
        assert_eq!(text.matches('\n').count(), src.matches('\n').count());
        let pos_orig = src.find("int y;").unwrap();
        let pos_out = text.find("int y;").unwrap();
        assert_eq!(pos_orig, pos_out);
    }

    #[test]
    fn stops_after_max_iterations_without_hanging() {
        // Pathological: many distinct unknown calling-convention macros in
        // sequence. Recovery should terminate (bounded by MAX_ITERATIONS)
        // rather than loop indefinitely, whether or not it fully clears.
        let mut src = String::new();
        for i in 0..20 {
            src.push_str(&format!(
                "typedef void (UNKNOWNCONV{i} PFNFOO{i})(int x);\n"
            ));
        }
        let mut parser = Parser::new();
        parser.set_language(&c_language()).unwrap();
        let (_, text) =
            parse_with_recovery(&mut parser, src.clone(), &RepairMacros::default()).unwrap();
        assert_eq!(text.len(), src.len());
    }
}
