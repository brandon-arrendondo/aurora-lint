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

/// Why a file was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Larger than the ceiling.
    TooLarge(String),
    /// Not text: a known binary format, or NUL bytes.
    NotText(String),
}

impl Refusal {
    /// The short cause word for a report.
    pub fn cause(&self) -> &'static str {
        match self {
            Refusal::TooLarge(_) => "too large",
            Refusal::NotText(_) => "not source text",
        }
    }

    /// The detail.
    pub fn detail(&self) -> &str {
        match self {
            Refusal::TooLarge(s) | Refusal::NotText(s) => s,
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
