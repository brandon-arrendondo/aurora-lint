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
//! This is deliberately minimal -- a size ceiling and a non-text sniff -- and
//! everything sits behind `admit`, so a fuller content classifier can
//! replace the body without touching a caller.

use std::io::Read;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};

/// The default size ceiling, in MiB. The largest file the benchmark corpora
/// scan is about 4 MiB (raylib's single-header `miniaudio.h`); the largest
/// real C inputs anyone hands a scanner are amalgamations and SDK headers of
/// about 9-10 MiB (sqlite3.c, the Windows SDK's biggest WinRT header). 64 MiB
/// is several times either, so no real source is refused, while a stray
/// archive or image named `.c` is.
pub const DEFAULT_MAX_FILE_MIB: u64 = 64;

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

/// How many leading bytes the sniff reads.
const SNIFF_BYTES: usize = 8192;

/// Whether `path` may be parsed as C source. The one gate every scanned and
/// prescanned file passes (see the module doc). A file that cannot be read
/// is admitted, so the parser reports the read error as it always has.
pub fn admit(path: &Path) -> Result<(), Refusal> {
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(());
    };
    if let Some(limit) = max_bytes() {
        if meta.len() > limit {
            return Err(Refusal::TooLarge(format!(
                "{} MiB is over --max-file-size {} MiB",
                meta.len().div_ceil(1024 * 1024),
                limit / (1024 * 1024)
            )));
        }
    }
    let mut head = Vec::with_capacity(SNIFF_BYTES);
    if let Ok(f) = std::fs::File::open(path) {
        let _ = f.take(SNIFF_BYTES as u64).read_to_end(&mut head);
    }
    sniff(&head).map_err(Refusal::NotText)
}

/// The non-text check on a file's first bytes.
fn sniff(head: &[u8]) -> Result<(), String> {
    // A UTF-16 or UTF-32 byte-order mark is text the parser transcodes
    // (Visual Studio writes UTF-16LE sources), NULs and all.
    const BOMS: &[&[u8]] = &[
        &[0xFF, 0xFE, 0x00, 0x00],
        &[0x00, 0x00, 0xFE, 0xFF],
        &[0xFF, 0xFE],
        &[0xFE, 0xFF],
    ];
    if BOMS.iter().any(|bom| head.starts_with(bom)) {
        return Ok(());
    }
    const MAGIC: &[(&[u8], &str)] = &[
        (b"\x7fELF", "an ELF binary"),
        (b"PK\x03\x04", "a zip archive"),
        (b"PK\x05\x06", "a zip archive"),
        (b"\x1f\x8b", "a gzip stream"),
        (b"BZh", "a bzip2 stream"),
        (b"\xfd7zXZ\x00", "an xz stream"),
        (b"7z\xbc\xaf\x27\x1c", "a 7z archive"),
        (b"\x28\xb5\x2f\xfd", "a zstd stream"),
        (b"!<arch>\n", "an ar archive"),
        (b"%PDF-", "a PDF document"),
        (b"\x89PNG", "a PNG image"),
        (b"\xff\xd8\xff", "a JPEG image"),
        (b"GIF8", "a GIF image"),
        (b"\xca\xfe\xba\xbe", "a Mach-O or Java class file"),
        (b"\xcf\xfa\xed\xfe", "a Mach-O binary"),
        (b"\xce\xfa\xed\xfe", "a Mach-O binary"),
    ];
    if let Some((_, what)) = MAGIC.iter().find(|(magic, _)| head.starts_with(magic)) {
        return Err(format!("starts like {what}"));
    }
    if head.len() > 262 && &head[257..262] == b"ustar" {
        return Err("starts like a tar archive".to_string());
    }
    if let Some(at) = head.iter().position(|&b| b == 0) {
        return Err(format!("NUL byte at offset {at}"));
    }
    Ok(())
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
    fn c_source_passes() {
        assert_eq!(
            sniff(b"#include <stdio.h>\nint main(void) { return 0; }\n"),
            Ok(())
        );
        assert_eq!(sniff(b""), Ok(()));
    }

    #[test]
    fn utf16_with_a_bom_passes_despite_nuls() {
        assert_eq!(sniff(&[0xFF, 0xFE, b'#', 0, b'i', 0]), Ok(()));
    }

    #[test]
    fn binaries_and_archives_are_refused() {
        assert!(sniff(b"\x7fELF\x02\x01\x01").unwrap_err().contains("ELF"));
        assert!(sniff(b"PK\x03\x04rest").unwrap_err().contains("zip"));
        assert!(sniff(b"\x1f\x8b\x08\x00").unwrap_err().contains("gzip"));
        let mut tar = vec![b'a'; 300];
        tar[257..262].copy_from_slice(b"ustar");
        assert!(sniff(&tar).unwrap_err().contains("tar"));
    }

    #[test]
    fn a_nul_byte_is_refused_with_its_offset() {
        assert_eq!(sniff(b"int x;\0"), Err("NUL byte at offset 6".to_string()));
    }
}
