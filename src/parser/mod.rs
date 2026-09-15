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

/// Read `file_path` as text and decode it by its byte-order mark, then
/// by content: UTF-16 (either endianness) when the file opens with a
/// UTF-16 BOM, UTF-8 otherwise (a UTF-8 BOM is dropped), with an
/// ISO-8859-1 transcode as the fallback for bytes that are neither.
///
/// The prior `fs::read_to_string`-only path failed silently on any
/// non-UTF-8 file, so pure-ftpd's 16 ISO-8859-encoded `messages_*.h`
/// translation headers were never analysed by any rule despite being in
/// scope per the corpus's README predicate (task 1061). ISO-8859-1 is a
/// single-byte encoding whose codepoints 0x00-0xFF map one-to-one onto
/// Unicode U+0000-U+00FF, so `b as char` for each byte is a lossless
/// transcode: any byte sequence becomes a valid `String`.
///
/// UTF-16 came with the first Windows-native corpus (Ventoy2Disk, the
/// suite's WIN*-C oracle): Visual Studio saves 4 of its 22 sources as
/// UTF-16LE with a BOM and 2 more as UTF-8 with a BOM. Fed through the
/// ISO-8859-1 fallback, a UTF-16 file becomes NUL-interleaved garbage
/// (`i\0n\0t\0 \0`) that the rule-independent parse stage chews on for
/// minutes -- WinDialog.c (2,434 lines) never finished -- and that no
/// rule could have reported a real finding on anyway. A UTF-8 BOM is
/// stripped rather than left as U+FEFF on line 1, where tree-sitter would
/// otherwise open the file with an ERROR node ahead of the first
/// declaration.
///
/// Without a BOM, the bytes themselves decide (task 1131). NUL never
/// belongs in C source -- a compiler drops it with a warning -- so any NUL
/// at all means the file is not the text its extension claims, and the
/// only question is which kind of not-text. A NUL in (nearly) every
/// other byte, all on one parity, is UTF-16 without its BOM: the high
/// byte of every character below U+0100 is zero, so ASCII-dominated
/// source lights up one parity and leaves the other dark, and the lit
/// parity names the endianness. Anything else with NULs in it is treated
/// as binary and refused with [`NotSourceText`], which the scan loop
/// reports as a warning and skips. Refusing is the point: a NUL-strewn
/// file parses to one flat `ERROR` root with a child per stray byte, and
/// the `node.child(i)` walk every pass and rule uses is quadratic on that
/// shape -- WinDialog.c, decoded as ISO-8859-1, pegged a core for over ten
/// minutes with every rule disabled, and no finding it could have produced
/// would have been real. Skipping with a diagnostic is strictly better
/// than analysing garbage silently, which is what the run did before.
///
/// Byte offsets in the returned string are not the same as offsets in
/// the file (high bytes expand to two UTF-8 bytes, UTF-16 units shrink
/// to one), but every downstream pass -- tree-sitter parsing,
/// `get_node_text`, position reporting -- works from the returned
/// string, so consistency is what matters, not exact file-offset
/// correspondence.
fn read_source_or_transcode(file_path: &str) -> Result<String> {
    let bytes =
        fs::read(file_path).with_context(|| format!("Failed to read file: {}", file_path))?;
    Ok(decode_source_bytes(bytes)?)
}

/// A file [`read_source_or_transcode`] refused because its bytes contain
/// NULs in no recognisable text layout -- a binary blob carrying a C
/// extension. Its own type so the scan loop can tell "not text, skipped"
/// (worth a warning) from an I/O failure. Carries the NUL count so the
/// warning can say why the file was judged binary.
#[derive(Debug)]
pub struct NotSourceText {
    /// How many NUL bytes the file held.
    pub nul_bytes: usize,
}

impl std::fmt::Display for NotSourceText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "not C source text ({} NUL bytes with no UTF-16 layout); skipped",
            self.nul_bytes
        )
    }
}

impl std::error::Error for NotSourceText {}

/// The decoding half of [`read_source_or_transcode`], split out so the
/// encodings can be tested without touching the filesystem.
fn decode_source_bytes(bytes: Vec<u8>) -> std::result::Result<String, NotSourceText> {
    let utf16 = |payload: &[u8], unit: fn([u8; 2]) -> u16| -> String {
        // An odd trailing byte is not half of anything; drop it rather
        // than fail the whole file over one byte.
        let units = payload.chunks_exact(2).map(|c| unit([c[0], c[1]]));
        char::decode_utf16(units)
            .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    };
    Ok(match bytes.as_slice() {
        [0xFF, 0xFE, payload @ ..] => utf16(payload, u16::from_le_bytes),
        [0xFE, 0xFF, payload @ ..] => utf16(payload, u16::from_be_bytes),
        _ => match sniff_nul_layout(&bytes) {
            NulLayout::None => match String::from_utf8(bytes) {
                Ok(mut s) => {
                    if s.starts_with('\u{FEFF}') {
                        s.drain(..'\u{FEFF}'.len_utf8());
                    }
                    s
                }
                Err(e) => e.into_bytes().iter().map(|&b| b as char).collect(),
            },
            NulLayout::Utf16Le => utf16(&bytes, u16::from_le_bytes),
            NulLayout::Utf16Be => utf16(&bytes, u16::from_be_bytes),
            NulLayout::Scattered { nul_bytes } => return Err(NotSourceText { nul_bytes }),
        },
    })
}

/// What the NUL bytes of a BOM-less file say about its encoding.
#[derive(Debug, PartialEq, Eq)]
enum NulLayout {
    /// No NUL anywhere: ordinary single-byte or UTF-8 text.
    None,
    /// NULs sit on the odd bytes (the high half of little-endian units).
    Utf16Le,
    /// NULs sit on the even bytes (the high half of big-endian units).
    Utf16Be,
    /// NULs with no parity pattern: not text in any encoding this reads.
    Scattered { nul_bytes: usize },
}

/// Classify `bytes` by where its NULs fall. UTF-16 needs the lit parity to
/// be at least half NUL (every character below U+0100 contributes one, so
/// this holds for any source whose text is at least half Latin) and the
/// other parity almost never NUL (a character whose LOW byte is zero --
/// U+0100, U+4E00 -- is one in 256 of the non-Latin ones, so 5% is well
/// clear of real text and well short of a blob's uniform spread).
fn sniff_nul_layout(bytes: &[u8]) -> NulLayout {
    let (mut nul_even, mut nul_odd) = (0usize, 0usize);
    for (i, &b) in bytes.iter().enumerate() {
        if b == 0 {
            if i % 2 == 0 {
                nul_even += 1;
            } else {
                nul_odd += 1;
            }
        }
    }
    if nul_even == 0 && nul_odd == 0 {
        return NulLayout::None;
    }
    let even_slots = bytes.len().div_ceil(2);
    let odd_slots = bytes.len() / 2;
    let is_utf16 = |lit: usize, lit_slots: usize, dark: usize, dark_slots: usize| {
        lit * 2 >= lit_slots && dark * 20 <= dark_slots
    };
    if is_utf16(nul_odd, odd_slots, nul_even, even_slots) {
        NulLayout::Utf16Le
    } else if is_utf16(nul_even, even_slots, nul_odd, odd_slots) {
        NulLayout::Utf16Be
    } else {
        NulLayout::Scattered {
            nul_bytes: nul_even + nul_odd,
        }
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
    fn decode_source_utf16le_bom_yields_the_text_not_nul_interleaved_bytes() {
        // "int x;\n" as Visual Studio writes it: FF FE BOM, then one
        // little-endian code unit per character.
        let mut bytes = vec![0xFF, 0xFE];
        for u in "int x;\n".encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(decode_source_bytes(bytes).unwrap(), "int x;\n");
    }

    #[test]
    fn decode_source_utf16be_bom_is_honoured_too() {
        let mut bytes = vec![0xFE, 0xFF];
        for u in "int y;\n".encode_utf16() {
            bytes.extend_from_slice(&u.to_be_bytes());
        }
        assert_eq!(decode_source_bytes(bytes).unwrap(), "int y;\n");
    }

    #[test]
    fn decode_source_strips_a_utf8_bom() {
        let bytes = b"\xEF\xBB\xBFint z;\n".to_vec();
        assert_eq!(decode_source_bytes(bytes).unwrap(), "int z;\n");
    }

    #[test]
    fn decode_source_utf16_odd_trailing_byte_is_dropped_not_fatal() {
        let mut bytes = vec![0xFF, 0xFE];
        for u in "ab".encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        bytes.push(0x63); // half of a code unit
        assert_eq!(decode_source_bytes(bytes).unwrap(), "ab");
    }

    #[test]
    fn decode_source_bomless_utf16le_is_recognised_by_its_nul_parity() {
        // WinDialog.c's shape minus the BOM: every character below U+0100
        // puts a NUL on the odd byte and nothing on the even one.
        let text = "int x = 1; /* 注释 */\nvoid f(void) {}\n";
        let mut bytes = Vec::new();
        for u in text.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(sniff_nul_layout(&bytes), NulLayout::Utf16Le);
        assert_eq!(decode_source_bytes(bytes).unwrap(), text);
    }

    #[test]
    fn decode_source_bomless_utf16be_is_recognised_too() {
        let text = "int y;\n";
        let mut bytes = Vec::new();
        for u in text.encode_utf16() {
            bytes.extend_from_slice(&u.to_be_bytes());
        }
        assert_eq!(sniff_nul_layout(&bytes), NulLayout::Utf16Be);
        assert_eq!(decode_source_bytes(bytes).unwrap(), text);
    }

    #[test]
    fn decode_source_refuses_scattered_nuls_as_binary() {
        // A blob: NULs on both parities, no text layout.
        let bytes = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00int\x00".to_vec();
        assert!(matches!(
            sniff_nul_layout(&bytes),
            NulLayout::Scattered { nul_bytes: 10 }
        ));
        let err = decode_source_bytes(bytes).unwrap_err();
        assert_eq!(err.nul_bytes, 10);
    }

    #[test]
    fn decode_source_a_single_stray_nul_in_text_is_still_not_utf16() {
        // One NUL in otherwise plain UTF-8 lights neither parity enough to
        // read as UTF-16, so it is refused rather than mis-decoded.
        let bytes = b"int a;\x00int b;\n".to_vec();
        assert!(matches!(
            sniff_nul_layout(&bytes),
            NulLayout::Scattered { nul_bytes: 1 }
        ));
        assert!(decode_source_bytes(bytes).is_err());
    }

    #[test]
    fn decode_source_nul_free_bytes_take_the_utf8_path_unchanged() {
        assert_eq!(sniff_nul_layout(b"int q;\n"), NulLayout::None);
        assert_eq!(
            decode_source_bytes(b"int q;\n".to_vec()).unwrap(),
            "int q;\n"
        );
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
