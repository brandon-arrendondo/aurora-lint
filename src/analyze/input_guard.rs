//! Refuse input that is not C source before the parser sees it (ADR-0017).
//!
//! aurora-lint picks files by extension, so whatever is named `.c` or `.h`
//! reaches the parser: a 2 GB archive, an ELF binary, a core dump. Parsing
//! that cannot produce a finding and can exhaust memory, and an
//! out-of-memory kill cannot be contained after the fact, so it has to be
//! prevented. [`admit`] is the one gate: a file it refuses is skipped and
//! reported (exit 3, a stderr line, a SARIF notification), never parsed and
//! never silently dropped.
//!
//! The decision is the shared parsing substrate's classifier
//! (`lang_parsing_substrate::classify_file`), so every tool built on it
//! refuses input the same way; `admit` adds only this tool's policy: the size
//! ceiling, admitting empty files, and refusing what cannot be classified.

use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};

/// The default size ceiling, in MiB. The largest file the benchmark corpora
/// scan is about 4 MiB (raylib's single-header `miniaudio.h`); the largest
/// real C inputs anyone hands a scanner are amalgamations and SDK headers of
/// about 9-10 MiB (sqlite3.c, the Windows SDK's biggest WinRT header). 64 MiB
/// is several times either, so no real source is refused, while a stray
/// archive or image named `.c` is.
pub const DEFAULT_MAX_FILE_MIB: u64 = 64;

/// [`DEFAULT_MAX_FILE_MIB`] as the command line's default text.
pub const DEFAULT_MAX_FILE_MIB_ARG: &str = "64";

/// Files above this size are analysed one at a time, so several huge inputs
/// cannot be in memory at once on a parallel scan. Above every file the
/// corpora contain, so an ordinary scan never waits on it.
pub const SERIALIZE_ABOVE_BYTES: u64 = 8 * 1024 * 1024;

static MAX_BYTES: OnceLock<Mutex<Option<u64>>> = OnceLock::new();

fn max_bytes_cell() -> &'static Mutex<Option<u64>> {
    MAX_BYTES.get_or_init(|| Mutex::new(Some(DEFAULT_MAX_FILE_MIB * 1024 * 1024)))
}

/// Set the size ceiling (`--max-file-size`, in MiB; `None` = no ceiling).
pub fn set_max_file_mib(mib: Option<u64>) {
    *max_bytes_cell().lock().unwrap_or_else(|e| e.into_inner()) =
        mib.map(|m| m.saturating_mul(1024 * 1024));
}

fn max_bytes() -> Option<u64> {
    *max_bytes_cell().lock().unwrap_or_else(|e| e.into_inner())
}

/// The size ceiling in force as a prescan cache records it: bytes, or
/// `none`. A file over it contributes no facts, so a cache built under one
/// ceiling is not the context for another.
pub fn max_file_size_key() -> String {
    max_bytes().map_or_else(|| "none".to_string(), |b| b.to_string())
}

/// Why a file was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Larger than the ceiling.
    TooLarge(String),
    /// Not text: a known binary format, or NUL bytes.
    NotText(String),
    /// Parsed, but nested deeper than `--max-nesting-depth`.
    TooDeep(String),
}

impl Refusal {
    /// The short cause word for a report.
    pub fn cause(&self) -> &'static str {
        match self {
            Refusal::TooLarge(_) => "too large",
            Refusal::NotText(_) => "not source text",
            Refusal::TooDeep(_) => "too deep",
        }
    }

    /// The detail.
    pub fn detail(&self) -> &str {
        match self {
            Refusal::TooLarge(s) | Refusal::NotText(s) | Refusal::TooDeep(s) => s,
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.cause(), self.detail())
    }
}

impl std::error::Error for Refusal {}

/// The deepest parse tree a file may have by default. Many analyses, in the
/// prescan and in the rules, walk the tree by recursion, once per level, and
/// a stack overflow aborts the whole process before containment can see it
/// (ADR-0017). A file nested deeper than the limit is refused after parsing,
/// with its depth, so a scan of it is reported incomplete rather than ended.
///
/// Measured against the scan's [`WORKER_STACK_BYTES`]: every input shape the
/// robustness suite generates (braces, parentheses, operator chains, `else
/// if` ladders) is walked by the prescan and the rules at twice this depth
/// without overflowing, and most overflow by four times. Hand-written C
/// stays far below it.
///
/// [`WORKER_STACK_BYTES`]: crate::analyze::WORKER_STACK_BYTES
pub const DEFAULT_MAX_NESTING_DEPTH: usize = 5_000;

/// [`DEFAULT_MAX_NESTING_DEPTH`] as the command line's default text.
pub const DEFAULT_MAX_NESTING_DEPTH_ARG: &str = "5000";

static MAX_DEPTH: OnceLock<Mutex<Option<usize>>> = OnceLock::new();

fn max_depth_cell() -> &'static Mutex<Option<usize>> {
    MAX_DEPTH.get_or_init(|| Mutex::new(Some(DEFAULT_MAX_NESTING_DEPTH)))
}

/// Set the nesting limit (`--max-nesting-depth`; `None` = no limit).
pub fn set_max_nesting_depth(levels: Option<usize>) {
    *max_depth_cell().lock().unwrap_or_else(|e| e.into_inner()) = levels;
}

fn max_depth() -> Option<usize> {
    *max_depth_cell().lock().unwrap_or_else(|e| e.into_inner())
}

/// The nesting limit in force as a prescan cache records it: levels, or
/// `none`. Like [`max_file_size_key`]: a refused file contributes no facts.
pub fn max_nesting_depth_key() -> String {
    max_depth().map_or_else(|| "none".to_string(), |d| d.to_string())
}

/// Whether a parsed file is shallow enough to analyse: its tree is at most
/// `--max-nesting-depth` levels deep.
pub fn admit_tree(tree: &tree_sitter::Tree) -> Result<(), Refusal> {
    admit_tree_under(tree, max_depth())
}

fn admit_tree_under(tree: &tree_sitter::Tree, limit: Option<usize>) -> Result<(), Refusal> {
    let Some(limit) = limit else {
        return Ok(());
    };
    let depth = tree_depth(tree);
    if depth > limit {
        return Err(Refusal::TooDeep(format!(
            "its syntax tree nests {depth} levels deep, over --max-nesting-depth {limit}"
        )));
    }
    Ok(())
}

/// The number of levels below the root of `tree`'s deepest node, by one
/// iterative walk.
pub fn tree_depth(tree: &tree_sitter::Tree) -> usize {
    let mut cursor = tree.walk();
    let (mut depth, mut deepest) = (0usize, 0usize);
    loop {
        if cursor.goto_first_child() {
            depth += 1;
            deepest = deepest.max(depth);
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return deepest;
            }
            depth -= 1;
        }
    }
}

/// Whether `path` may be parsed as C source. The one gate every scanned and
/// prescanned file passes (see the module doc). The decision is the shared
/// parsing substrate's heuristic classifier
/// (`lang_parsing_substrate::classify_file`: magic numbers, then the ratio
/// of NUL, control and invalid-UTF-8 bytes in the first 8 KiB, then the
/// size), so every tool built on the substrate refuses input the same way.
///
/// Empty files are admitted: an empty `.c` is valid source with nothing in
/// it. A file that cannot be classified -- not a regular file (a FIFO or a
/// device, which a read can block on forever), or unreadable -- is refused,
/// as is any classification this version does not know: neither is source
/// the parser should be handed.
pub fn admit(path: &Path) -> Result<(), Refusal> {
    use lang_parsing_substrate::{classify_file, ClassifyLimits, FileClass};
    let limits = ClassifyLimits {
        max_size: max_bytes(),
        ..ClassifyLimits::default()
    };
    match classify_file(path, &limits) {
        Ok(FileClass::Oversize { size, limit }) => Err(Refusal::TooLarge(format!(
            "{} MiB is over --max-file-size {} MiB",
            size.div_ceil(1024 * 1024),
            limit / (1024 * 1024)
        ))),
        Ok(FileClass::Binary { kind, mime }) => Err(Refusal::NotText(match mime {
            Some(mime) => format!("looks like binary data ({kind:?}, {mime})"),
            None => format!("looks like binary data ({kind:?})"),
        })),
        Ok(FileClass::Empty) | Ok(FileClass::SourceText(_)) => Ok(()),
        Ok(other) => Err(Refusal::NotText(format!(
            "unrecognised file classification {other:?}"
        ))),
        Err(e) => Err(Refusal::NotText(format!(
            "cannot be classified as a regular readable file ({e})"
        ))),
    }
}

/// Held while a file over [`SERIALIZE_ABOVE_BYTES`] is analysed: one huge
/// file at a time, whatever `--jobs` says. `None` for an ordinary file.
pub fn large_file_permit(path: &Path) -> Option<MutexGuard<'static, ()>> {
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
    let len = std::fs::metadata(path).ok()?.len();
    (len > SERIALIZE_ABOVE_BYTES).then(|| ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_line_default_matches() {
        assert_eq!(
            DEFAULT_MAX_FILE_MIB_ARG.parse::<u64>().unwrap(),
            DEFAULT_MAX_FILE_MIB
        );
        assert_eq!(
            DEFAULT_MAX_NESTING_DEPTH_ARG.parse::<usize>().unwrap(),
            DEFAULT_MAX_NESTING_DEPTH
        );
    }

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&lang_parsing_substrate::tree_sitter_c::LANGUAGE.into())
            .unwrap();
        parser.parse(source, None).unwrap()
    }

    #[test]
    fn depth_counts_levels_below_the_root() {
        // translation_unit > declaration > init_declarator > number_literal
        assert_eq!(tree_depth(&parse("int x = 1;")), 3);
        let nested = format!("int y = {}1{};", "(".repeat(50), ")".repeat(50));
        assert_eq!(tree_depth(&parse(&nested)), 53);
        assert_eq!(tree_depth(&parse("")), 0);
    }

    #[test]
    fn a_tree_deeper_than_the_limit_is_refused_with_its_depth() {
        let nested = parse(&format!("int y = {}1{};", "(".repeat(50), ")".repeat(50)));
        assert_eq!(admit_tree_under(&nested, Some(53)), Ok(()));
        assert_eq!(admit_tree_under(&nested, None), Ok(()));
        let refused = admit_tree_under(&nested, Some(52)).unwrap_err();
        assert_eq!(refused.cause(), "too deep");
        assert!(refused.detail().contains("53 levels deep"), "{refused}");
        assert!(
            refused.detail().contains("--max-nesting-depth 52"),
            "{refused}"
        );
    }

    fn file(bytes: &[u8]) -> tempfile::NamedTempFile {
        let f = tempfile::Builder::new().suffix(".c").tempfile().unwrap();
        std::fs::write(f.path(), bytes).unwrap();
        f
    }

    #[test]
    fn c_source_and_empty_files_pass() {
        assert_eq!(
            admit(file(b"#include <stdio.h>\nint main(void) { return 0; }\n").path()),
            Ok(())
        );
        assert_eq!(admit(file(b"").path()), Ok(()));
    }

    #[test]
    fn utf16_with_a_bom_passes_despite_nuls() {
        assert_eq!(
            admit(file(&[0xFF, 0xFE, b'#', 0, b'i', 0, b'n', 0]).path()),
            Ok(())
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe.c");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(matches!(admit(&fifo), Err(Refusal::NotText(_))));
    }

    #[test]
    fn binaries_are_refused() {
        let mut header = b"\x7fELF\x02\x01\x01".to_vec();
        header.resize(64, 0);
        let elf = admit(file(&header).path());
        assert!(
            matches!(&elf, Err(Refusal::NotText(d)) if d.contains("Elf")),
            "{elf:?}"
        );
        let nuls = admit(
            file(
                &[b'x'; 16]
                    .iter()
                    .chain([0u8; 32].iter())
                    .copied()
                    .collect::<Vec<_>>(),
            )
            .path(),
        );
        assert!(matches!(nuls, Err(Refusal::NotText(_))));
    }
}
