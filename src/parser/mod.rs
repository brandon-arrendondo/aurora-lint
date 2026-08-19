use anyhow::{Context, Result};
use std::fs;
use tree_sitter::{Language, Parser, Tree};

/// The tree-sitter C grammar, sourced from the shared lang-parsing-substrate.
/// Single point of truth for the grammar so rules don't depend on
/// `tree-sitter-c` directly.
pub fn c_language() -> Language {
    lang_parsing_substrate::tree_sitter_c::LANGUAGE.into()
}

/// A tree-sitter C parser, with sqc's pre-parse source-repair passes wired
/// into `parse_file`/`parse_source`.
pub struct CParser {
    parser: Parser,
}

impl CParser {
    /// A parser configured with the C grammar.
    pub fn new() -> Result<Self> {
        let mut parser = Parser::new();
        parser
            .set_language(&c_language())
            .context("Failed to set C language for parser")?;

        Ok(Self { parser })
    }

    /// Read and parse `file_path`, applying the source-repair passes
    /// documented inline below, and returning the (possibly repaired)
    /// source alongside the parse tree.
    pub fn parse_file(&mut self, file_path: &str) -> Result<(Tree, String)> {
        let source = fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read file: {}", file_path))?;
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

        // Task 437: if a parse error remains (e.g. an externally-defined
        // attribute macro with no local #define for the pass above to
        // find), iteratively blank single-token unknown-identifier ERROR
        // nodes and re-parse. Length-preserving and bounded; a no-op reparse
        // when the first parse already has no error.
        let (tree, source) = crate::analyze::unknown_identifier_recovery::parse_with_recovery(
            &mut self.parser,
            source,
        )
        .with_context(|| format!("Failed to parse file: {}", file_path))?;

        Ok((tree, source))
    }

    /// Parse `source` directly (no file read), applying the same
    /// source-repair passes as [`Self::parse_file`].
    #[allow(dead_code)]
    pub fn parse_source(&mut self, source: &str) -> Result<Tree> {
        let source = crate::analyze::empty_macro_blank::blank_empty_object_macros(source);
        let source = crate::analyze::preproc_dangling_else::blank_dangling_else_preproc(&source);
        let (tree, _) = crate::analyze::unknown_identifier_recovery::parse_with_recovery(
            &mut self.parser,
            source,
        )
        .context("Failed to parse source code")?;
        Ok(tree)
    }
}

impl Default for CParser {
    fn default() -> Self {
        Self::new().expect("Failed to create C parser")
    }
}
