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
        let source = crate::analyze::empty_macro_blank::blank_empty_object_macros(source);
        let source = crate::analyze::preproc_dangling_else::blank_dangling_else_preproc(&source);
        let source = crate::analyze::label_preproc_guard::blank_label_guarded_preproc(&source);
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
