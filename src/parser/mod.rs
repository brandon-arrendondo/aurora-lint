use anyhow::{Context, Result};
use std::fs;
use tree_sitter::{Language, Parser, Tree};

/// The tree-sitter C grammar, sourced from the shared lang-parsing-substrate.
/// Single point of truth for the grammar so rules don't depend on
/// `tree-sitter-c` directly.
pub fn c_language() -> Language {
    lang_parsing_substrate::tree_sitter_c::LANGUAGE.into()
}

pub struct CParser {
    parser: Parser,
}

impl CParser {
    pub fn new() -> Result<Self> {
        let mut parser = Parser::new();
        parser
            .set_language(&c_language())
            .context("Failed to set C language for parser")?;

        Ok(Self { parser })
    }

    pub fn parse_file(&mut self, file_path: &str) -> Result<(Tree, String)> {
        let source = fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read file: {}", file_path))?;

        let tree = self
            .parser
            .parse(&source, None)
            .with_context(|| format!("Failed to parse file: {}", file_path))?;

        Ok((tree, source))
    }

    #[allow(dead_code)]
    pub fn parse_source(&mut self, source: &str) -> Result<Tree> {
        self.parser
            .parse(source, None)
            .context("Failed to parse source code")
    }
}

impl Default for CParser {
    fn default() -> Self {
        Self::new().expect("Failed to create C parser")
    }
}
