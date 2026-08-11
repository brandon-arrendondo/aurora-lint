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
        *b = b' ';
    }
    // Safe: only ASCII identifier bytes (already validated by
    // `is_bare_identifier`) are replaced with ASCII spaces.
    String::from_utf8(bytes).unwrap_or_else(|_| source.to_string())
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
        let Some((start, end)) = find_blankable_identifier_error(&tree.root_node(), &text) else {
            break;
        };
        text = blank_range(&text, start, end);
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
