use anyhow::{Context, Result};
use std::fs;
use std::sync::Arc;
use tree_sitter::{Language, Parser, Tree};

use crate::analyze::context::ProjectContext;
use crate::analyze::unknown_identifier_recovery::RepairMacros;

/// The tree-sitter C grammar, sourced from the shared lang-parsing-substrate.
/// Single point of truth for the grammar so rules don't depend on
/// `tree-sitter-c` directly.
pub fn c_language() -> Language {
    lang_parsing_substrate::tree_sitter_c::LANGUAGE.into()
}

/// A tree-sitter C parser, with aurora-lint's pre-parse source-repair passes wired
/// into `parse_file`/`parse_source`.
pub struct CParser {
    parser: Parser,
    /// Project-wide macro knowledge for the parse-repair pass. Empty until
    /// [`Self::set_repair_macros`] is called, which is what the prescan (and
    /// any single-file caller) relies on -- it is itself the pass that
    /// collects these. `Arc` because the analysis driver builds one parser
    /// per file.
    repair_macros: Arc<RepairMacros>,
}

impl CParser {
    /// A parser configured with the C grammar.
    pub fn new() -> Result<Self> {
        let mut parser = Parser::new();
        parser
            .set_language(&c_language())
            .context("Failed to set C language for parser")?;

        Ok(Self {
            parser,
            repair_macros: Arc::new(RepairMacros::default()),
        })
    }

    /// Hand the parse-repair pass the prescan's macro table, so it can blank
    /// the macro rather than the real type or declarator tree-sitter
    /// stranded next to it (task 1019). Call once per parser, after the
    /// prescan has run; without it the pass falls back to blanking the
    /// stranded token.
    pub fn set_repair_macros(&mut self, macros: Arc<RepairMacros>) {
        self.repair_macros = macros;
    }

    /// [`Self::set_repair_macros`] straight from a [`ProjectContext`], for
    /// callers that hold one rather than a shared table. Used by the
    /// generated fixture tests, hence dead in the binary build.
    #[allow(dead_code)]
    pub fn set_repair_macros_from_context(&mut self, context: &ProjectContext) {
        self.repair_macros = Arc::new(RepairMacros::from_context(context));
    }

    /// Read and parse `file_path`, applying the source-repair passes
    /// documented inline below, and returning the (possibly repaired)
    /// source alongside the parse tree.
    pub fn parse_file(&mut self, file_path: &str) -> Result<(Tree, String)> {
        let source = read_source_or_transcode(file_path)?;
        // Task 1043: neutralize emscripten EM_ASM/EM_JS embedded-JavaScript
        // macro bodies. A JS block parses as ordinary-looking C rather than
        // an ERROR node, so without this every rule walks it -- DCL31-C
        // reported every JS call in reach as an undeclared function, the JS
        // keyword `function` among them. Runs first so the passes below see
        // only C. Length- and newline-preserving.
        let source = crate::analyze::embedded_js_blank::blank_embedded_js(&source);

        // Task 435: blank empty WINAPI/RLAPI-style export-specifier macros
        // before parsing -- tree-sitter-c's grammar can't parse a bare
        // identifier immediately before a declaration's type, and the
        // resulting ERROR-node recovery can swallow unrelated content later
        // in the file. Length-preserving, so all positions below are
        // unaffected by this substitution.
        let source = crate::analyze::empty_macro_blank::blank_empty_object_macros(&source);

        // Task 441: blank #if/#ifdef/#ifndef + #endif directive pairs that
        // wrap a dangling `else` fragment (an if/else-if chain split across
        // a build-time feature guard) -- tree-sitter-c's grammar has no
        // production for that incomplete-statement shape and can misparse
        // it into a bogus nested construct rather than a small, isolated
        // ERROR node. Purely text-level and length-preserving, so it runs
        // unconditionally rather than gated on a parse error being present.
        let source = crate::analyze::preproc_dangling_else::blank_dangling_else_preproc(&source);

        // Task 647: blank a #if/#ifdef/#ifndef + matching #endif pair that
        // opens immediately after a bare goto-label line -- tree-sitter-c's
        // `labeled_statement` grammar rule requires exactly one statement
        // right after the label and has no alternative for a preprocessor
        // directive there, so GLR error recovery mis-parses the first
        // guarded statement into a bogus declaration and silently detaches
        // every later statement in the block from its #ifdef ancestor.
        // Purely text-level and length-preserving, so it runs
        // unconditionally like the pass above.
        let source = crate::analyze::label_preproc_guard::blank_label_guarded_preproc(&source);

        // Task 1044: blank a #if/#ifdef/#ifndef + matching #endif pair that
        // opens inside an unclosed parenthesized expression (a build-time-
        // optional operand of a condition, or entry in a parameter or
        // argument list). tree-sitter-c has no production for a
        // preprocessor conditional between two operands, and which repair
        // GLR error recovery picks depends on tokens far away -- on
        // pure-ftpd's ls.c a one-statement edit at the end of the file
        // flipped `listfile` between a normal function_definition and a
        // single ERROR node spanning everything from it to EOF, hiding the
        // definition from every rule while leaving its calls visible.
        let source = crate::analyze::paren_preproc_guard::blank_paren_guarded_preproc(&source);

        // Task 1066: a guard that falls between a control-flow header and the
        // body it governs (`#if ...` / `if (cond)` / `#endif` / `{ ... }`).
        // `preproc_if` is a block item, so the brace block parses as a
        // SIBLING of the `if` and GLR recovery gives the `if` a synthesized
        // empty consequence -- which EXP19-C reads as an unbraced body.
        let source =
            crate::analyze::control_header_preproc_guard::blank_control_header_guarded_preproc(
                &source,
            );

        // Task 1070: the same split across a MULTI-ARM chain. The pass above
        // refuses those on purpose -- blanking a chain's directive lines
        // splices every arm into one statement stream, so the outer `if` gets
        // a non-compound consequence and EXP19-C fires MORE, not less. This
        // pass keeps one arm and blanks the other arms' dangling fragments.
        let source = crate::analyze::preproc_split_chain::blank_split_chain_preproc(&source);

        // Task 437: if a parse error remains (e.g. an externally-defined
        // attribute macro with no local #define for the pass above to
        // find), iteratively blank single-token unknown-identifier ERROR
        // nodes and re-parse. Length-preserving and bounded; a no-op reparse
        // when the first parse already has no error.
        let (tree, source) = crate::analyze::unknown_identifier_recovery::parse_with_recovery(
            &mut self.parser,
            source,
            &self.repair_macros,
        )
        .with_context(|| format!("Failed to parse file: {}", file_path))?;

        Ok((tree, source))
    }

    /// Parse `source` directly (no file read), applying the same
    /// source-repair passes as [`Self::parse_file`], and returning the
    /// (possibly repaired) source alongside the tree -- callers MUST use
    /// this returned string for any subsequent `get_node_text`-style byte
    /// extraction, not the original `source` argument. A repair pass is
    /// length- and line-count-preserving but not necessarily *content*-
    /// preserving on the lines it rewrites (e.g. `label_preproc_guard`
    /// leaves a recoverable marker comment rather than blank whitespace,
    /// task 663), so text sliced from the wrong string at an otherwise
    /// correct byte range can silently return stale content.
    pub fn parse_source(&mut self, source: &str) -> Result<(Tree, String)> {
        let source = crate::analyze::embedded_js_blank::blank_embedded_js(source);
        let source = crate::analyze::empty_macro_blank::blank_empty_object_macros(&source);
        let source = crate::analyze::preproc_dangling_else::blank_dangling_else_preproc(&source);
        let source = crate::analyze::label_preproc_guard::blank_label_guarded_preproc(&source);
        let source = crate::analyze::paren_preproc_guard::blank_paren_guarded_preproc(&source);
        let source =
            crate::analyze::control_header_preproc_guard::blank_control_header_guarded_preproc(
                &source,
            );
        let source = crate::analyze::preproc_split_chain::blank_split_chain_preproc(&source);
        let (tree, source) = crate::analyze::unknown_identifier_recovery::parse_with_recovery(
            &mut self.parser,
            source,
            &self.repair_macros,
        )
        .context("Failed to parse source code")?;
        Ok((tree, source))
    }
}

impl Default for CParser {
    fn default() -> Self {
        Self::new().expect("Failed to create C parser")
    }
}

/// Read `file_path` as text, falling back to an ISO-8859-1 transcode if
/// the bytes are not valid UTF-8. The prior `fs::read_to_string`-only
/// path failed silently on any non-UTF-8 file, so pure-ftpd's 16
/// ISO-8859-encoded `messages_*.h` translation headers have never been
/// analysed by any rule despite being in scope per the corpus's README
/// predicate (task 1061). No other pinned corpus contains a non-UTF-8
/// `.c`/`.h` file.
///
/// ISO-8859-1 is a single-byte encoding whose codepoints 0x00-0xFF map
/// one-to-one onto Unicode U+0000-U+00FF, so `b as char` for each byte
/// is a lossless transcode: any byte sequence becomes a valid `String`.
/// Byte offsets in the returned string are not the same as offsets in
/// the file (high bytes expand to two UTF-8 bytes), but every downstream
/// pass -- tree-sitter parsing, `get_node_text`, position reporting --
/// works from the returned string, so consistency is what matters, not
/// exact file-offset correspondence.
fn read_source_or_transcode(file_path: &str) -> Result<String> {
    let bytes =
        fs::read(file_path).with_context(|| format!("Failed to read file: {}", file_path))?;
    match String::from_utf8(bytes) {
        Ok(s) => Ok(s),
        Err(e) => Ok(e.into_bytes().iter().map(|&b| b as char).collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_source_transcodes_iso_8859_bytes_to_valid_utf8() {
        // High byte 0xE9 is `é` in ISO-8859-1 (Unicode U+00E9). Preceded
        // by ASCII, so the file as a whole is not valid UTF-8 (a lone
        // 0xE9 starts a 3-byte UTF-8 sequence that never arrives).
        let dir = std::env::temp_dir().join("aurora-lint-parser-iso8859-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("messages_iso.h");
        std::fs::write(&path, b"const char MSG[] = \"caf\xE9\";\n").unwrap();

        let s = read_source_or_transcode(path.to_str().unwrap()).unwrap();

        // Fast path via read_to_string would have errored on this input.
        assert!(s.contains("caf\u{00E9}"), "got {:?}", s);
        // Result is a valid Rust String, so downstream passes can slice
        // and re-parse it as UTF-8 unconditionally.
        assert!(s.is_char_boundary(s.len()));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn read_source_fast_path_returns_utf8_bytes_unchanged() {
        let dir = std::env::temp_dir().join("aurora-lint-parser-utf8-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("plain.c");
        let contents = "int f(void) { return 0; }\n";
        std::fs::write(&path, contents).unwrap();

        let s = read_source_or_transcode(path.to_str().unwrap()).unwrap();
        assert_eq!(s, contents);
        std::fs::remove_file(&path).ok();
    }
}
