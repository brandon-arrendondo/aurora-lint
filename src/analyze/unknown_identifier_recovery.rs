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
//! Task 438 added a second, differently-shaped recovery target to the same
//! loop: a lone `{`/`}` ERROR-wrapped inside a `#if defined(__cplusplus)`
//! (or `#ifdef`/`#elif`) conditional -- the dual-C/C++-header idiom for
//! guarding an `extern "C"` block's open/close brace. See
//! [`find_blankable_preproc_brace_error`] for why this one small, locally
//! contained defect was observed cascading into a file-spanning ERROR node
//! on raylib's rlgl.h.

use tree_sitter::{Node, Parser, Tree};

/// Each iteration is a full re-parse of the file; capped to bound worst-case
/// cost on a pathological input. Real files have needed at most a handful
/// of passes in testing (one distinct unknown-identifier name per pass, in
/// source order).
const MAX_ITERATIONS: u32 = 8;

/// C keywords that must never be blanked even when tree-sitter's error
/// recovery leaves one wrapped in a generic `identifier` leaf inside an
/// `ERROR` node. Found via a real regression: `STATIC void f(...) {}`
/// (`STATIC` a real, non-empty macro for `static`) parsed with `STATIC`
/// consumed as the declarator's `type_identifier` and `void` itself
/// stranded as an ERROR-wrapped `identifier` -- blanking "void" as if it
/// were an unknown macro discarded the function's actual return type,
/// which then made MSC37-C misjudge it as non-void and demand a return
/// statement. A keyword being inside an ERROR node is a sign the SURROUNDING
/// structure misparsed, not that the keyword itself is safely removable.
const C_KEYWORDS: &[&str] = &[
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

fn is_bare_identifier(text: &str) -> bool {
    if C_KEYWORDS.contains(&text) {
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
/// task 663 introduced for label-guarded preprocessor directives. Every
/// other unknown identifier is blanked exactly as before; only this
/// specific, safe, fixed name list gets the marker treatment.
fn blank_or_mark_noreturn(source: &str, start: usize, end: usize) -> String {
    let trimmed = source[start..end].trim();
    if crate::analyze::noreturn::NORETURN_ATTRIBUTE_MACRO_NAMES.contains(&trimmed) {
        if let Some(marked) = crate::analyze::noreturn::write_marker(source, start, end) {
            return marked;
        }
    }
    blank_range(source, start, end)
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
pub fn parse_with_recovery(parser: &mut Parser, source: String) -> Option<(Tree, String)> {
    let mut text = source;
    let mut tree = parser.parse(&text, None)?;

    for _ in 0..MAX_ITERATIONS {
        if !tree.root_node().has_error() {
            break;
        }
        if let Some((start, end)) = find_blankable_identifier_error(&tree.root_node(), &text) {
            text = blank_or_mark_noreturn(&text, start, end);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::c_language;

    fn recover(src: &str) -> (bool, String) {
        let mut parser = Parser::new();
        parser.set_language(&c_language()).unwrap();
        let (tree, text) = parse_with_recovery(&mut parser, src.to_string()).unwrap();
        (tree.root_node().has_error(), text)
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
        let (_, text) = parse_with_recovery(&mut parser, src.clone()).unwrap();
        assert_eq!(text.len(), src.len());
    }
}
