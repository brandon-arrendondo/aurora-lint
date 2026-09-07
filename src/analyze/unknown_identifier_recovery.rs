//! Iterative parse-error recovery for unknown bare identifiers that have no
//! local `#define` (task 437, follow-up to task 435's `empty_macro_blank`).
//!
//! Task 435 fixed the WINAPI/RLAPI-style export-macro idiom by blanking a
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
//! Task 1019 made the choice of WHICH token to blank macro-aware. Blanking
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
//! Task 438 added a second, differently-shaped recovery target to the same
//! loop: a lone `{`/`}` ERROR-wrapped inside a `#if defined(__cplusplus)`
//! (or `#ifdef`/`#elif`) conditional -- the dual-C/C++-header idiom for
//! guarding an `extern "C"` block's open/close brace. See
//! [`find_blankable_preproc_brace_error`] for why this one small, locally
//! contained defect was observed cascading into a file-spanning ERROR node
//! on raylib's rlgl.h.

use std::collections::HashSet;
use tree_sitter::{Node, Parser, Tree};

use crate::analyze::context::ProjectContext;

/// Project-wide macro knowledge the repair pass consults when deciding which
/// token to blank. Empty means "no prescan data" -- every decision then
/// falls back to the token tree-sitter stranded, which is what this pass did
/// before task 1019.
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
}

impl RepairMacros {
    /// The two macro sets the prescan already collects, copied out of a
    /// [`ProjectContext`].
    pub fn from_context(context: &ProjectContext) -> Self {
        Self {
            object_macros: context.defined_macro_names.clone(),
            unused_attribute_macros: context.unused_attribute_macros.clone(),
        }
    }
}

/// Marker written in place of a blanked [`RepairMacros::unused_attribute_macros`]
/// token, the same length-preserving recoverable-marker idiom task 663 uses
/// for label-guarded directives and task 648 for `NORETURN`. Without it the
/// declaration reaching MSC13-C reads `word_t totalObjectSize       ;` --
/// correctly parsed, correctly named, and with the annotation that makes it
/// legitimate silently gone (task 1019). Consumers must accept it both
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
    if node.kind() == "ERROR" {
        let start = node.start_byte();
        let end = node.end_byte();
        let text = &source[start..end];
        let trimmed = text.trim();
        if !trimmed.is_empty() && is_bare_identifier(trimmed) {
            let leading = text.len() - text.trim_start().len();
            let trailing = text.len() - text.trim_end().len();
            return Some((start + leading, end - trailing));
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if let Some(found) = find_blankable_identifier_error(&child, source) {
                return Some(found);
            }
        }
    }
    None
}

fn blank_range(source: &str, start: usize, end: usize) -> String {
    let mut bytes = source.as_bytes().to_vec();
    for b in bytes.iter_mut().take(end).skip(start) {
        // Newlines are preserved even inside a blanked range (task 438's
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

/// Same as [`blank_range`], but if the identifier being blanked is a known
/// noreturn-attribute macro name (task 648 -- e.g. seL4's
/// `void NORETURN slowpath(...)`, where `NORETURN` has no local `#define`
/// for `empty_macro_blank` to find and expands to
/// `__attribute__((noreturn))` in a header this single-file parse never
/// sees), write `crate::analyze::noreturn::MARKER` in its place instead of
/// plain blanking -- the same length-preserving recoverable-marker idiom
/// task 663 introduced for label-guarded preprocessor directives.
///
/// An unused-attribute macro (task 1019, resolved through the prescan's
/// [`RepairMacros::unused_attribute_macros`] rather than by spelling) leaves
/// [`UNUSED_ATTRIBUTE_MARKER`] behind for the same reason: what the macro
/// expanded to is the author's statement that the variable may go unread,
/// and blanking it hands MSC13-C a declaration with nothing left to read.
/// Every other unknown identifier is blanked exactly as before -- only these
/// two narrow, purpose-known cases get the marker treatment.
fn blank_or_mark(source: &str, start: usize, end: usize, macros: &RepairMacros) -> String {
    let trimmed = source[start..end].trim();
    if crate::analyze::noreturn::NORETURN_ATTRIBUTE_MACRO_NAMES.contains(&trimmed) {
        if let Some(marked) = crate::analyze::noreturn::write_marker(source, start, end) {
            return marked;
        }
    }
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

/// True if the line containing `byte` begins (ignoring leading whitespace)
/// with `#`.
fn line_is_preprocessor_directive(source: &str, byte: usize) -> bool {
    let line_start = source[..byte].rfind('\n').map_or(0, |i| i + 1);
    source[line_start..].trim_start().starts_with('#')
}

/// Number of `ERROR` and `MISSING` nodes in the tree -- the comparison used
/// to decide between two candidate repairs of the same defect.
fn error_node_count(node: &Node) -> usize {
    let mut count = usize::from(node.is_error() || node.is_missing());
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            count += error_node_count(&child);
        }
    }
    count
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
/// rlgl.h (task 438): the resulting ERROR, though itself small and locally
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
/// comment above. Task 464 found a false match on mosquitto's uthash.h:
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
    if matches!(
        node.kind(),
        "preproc_if" | "preproc_ifdef" | "preproc_elif" | "preproc_elifdef"
    ) {
        let children: Vec<Node> = (0..node.child_count())
            .filter_map(|i| node.child(i))
            .collect();
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
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if let Some(found) = find_blankable_preproc_brace_error(&child, source) {
                return Some(found);
            }
        }
    }
    None
}

/// Parse `source`, then iteratively blank and re-parse away any single-token
/// unknown-identifier `ERROR` node found, up to [`MAX_ITERATIONS`] times.
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
        if !tree.root_node().has_error() {
            break;
        }
        if let Some((start, end)) = find_blankable_identifier_error(&tree.root_node(), &text) {
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
        }
    }

    #[test]
    fn recovers_unknown_calling_convention_in_funcptr_typedef() {
        // GL_APIENTRYP has no local #define anywhere in this snippet --
        // task 435's fix has nothing to find here.
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
        // must keep behaving exactly as it did before task 1019.
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
        // Task 438: raylib rlgl.h's dual-C/C++ extern "C" guard idiom closes
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
        // Task 464: minimal reduction of mosquitto's deps/uthash.h. A
        // backslash-continued do/while(0) macro containing a switch/case
        // (HASH_SFH) makes tree-sitter-c's GLR recovery scatter several
        // small, unrelated single-token `{`/`}` ERROR nodes as *direct
        // children of the file's own top-level `#ifndef UTHASH_H` header
        // guard* -- not wrapped in their own `preproc_if`, unlike the
        // task-438 extern "C" idiom this recovery targets. The buggy
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
