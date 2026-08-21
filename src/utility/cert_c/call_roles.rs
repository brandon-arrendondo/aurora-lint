//! Shared call-role classification: "what kind of thing does this function
//! name do" (allocator, printf-family formatted-output, scanf-family
//! formatted-input, ...), as opposed to `std_functions`'s flat "is this a
//! known std/POSIX/Windows name at all."
//!
//! Filed as task 487 after task 481's ruleset-wide duplication sweep found
//! `is_allocation_call`/`is_alloc_call` reimplemented in 7 files with
//! disagreeing lists, and `is_printf_family` (or an equivalent list embedded
//! in a broader `is_safe_function`) reimplemented in 5+ files, each a
//! candidate source of rule-to-rule inconsistency. See
//! `docs/design/internal-capability-catalog.md`.
//!
//! Not every rule-local variant collapses into one of these: `MEM02-C`'s
//! allocator check deliberately excludes `strdup`/`strndup` (they return
//! `char *`, not `void *`, so MEM02-C's "must cast a void*-returning
//! allocator" rule doesn't apply) -- that's `is_heap_allocator`, distinct
//! from the broader `is_allocator_call`. `ARR30-C`'s buffer-size-tracking
//! allocator list and `MEM12-C`'s broader resource-acquisition list
//! (`fopen`/`open`/`socket`) are intentionally NOT folded in here yet --
//! both sit inside oversized, text-heuristic-heavy rule files flagged for
//! their own dedicated audit (tasks 492/493/497) before any migration.

/// Core heap allocators that return `void *` (the `MEM02-C` "must
/// immediately cast" set). Does NOT include `strdup`/`strndup`, which
/// return `char *` already.
const HEAP_ALLOC_FUNCS: &[&str] = &["malloc", "calloc", "realloc", "aligned_alloc"];

/// String-duplicating allocators -- also heap allocations, but typed
/// `char *` rather than `void *`.
const STRING_DUP_FUNCS: &[&str] = &["strdup", "strndup"];

/// printf-family formatted-output functions, including the `dprintf`/
/// `vdprintf` (fd-based) and wide-character (`wprintf`/`fwprintf`/
/// `swprintf`) variants. Union of every printf list found across
/// `FIO47-C`/`DCL10-C`/`DCL11-C` during the task-481 sweep -- FIO47-C's
/// version was the most complete of the three but still missed the
/// wide-character variants DCL11-C had.
const PRINTF_FUNCS: &[&str] = &[
    "printf",
    "fprintf",
    "sprintf",
    "snprintf",
    "vprintf",
    "vfprintf",
    "vsprintf",
    "vsnprintf",
    "dprintf",
    "vdprintf",
    "wprintf",
    "fwprintf",
    "swprintf",
];

/// scanf-family formatted-input functions.
const SCANF_FUNCS: &[&str] = &["scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf"];

/// A `void *`-returning heap allocator: `malloc`/`calloc`/`realloc`/
/// `aligned_alloc`. Use this (not [`is_allocator_call`]) when the rule's
/// concern is specifically the void-pointer-cast idiom.
pub fn is_heap_allocator(name: &str) -> bool {
    HEAP_ALLOC_FUNCS.contains(&name)
}

/// `strdup`/`strndup`.
pub fn is_string_duplicator(name: &str) -> bool {
    STRING_DUP_FUNCS.contains(&name)
}

/// Any heap-allocating call: [`is_heap_allocator`] or [`is_string_duplicator`].
/// This is the broader set most allocation-lifetime-tracking rules
/// (leak/free/thread-lifetime checks) actually want.
pub fn is_allocator_call(name: &str) -> bool {
    is_heap_allocator(name) || is_string_duplicator(name)
}

/// A printf-family formatted-output function.
pub fn is_printf_family(name: &str) -> bool {
    PRINTF_FUNCS.contains(&name)
}

/// A scanf-family formatted-input function.
pub fn is_scanf_family(name: &str) -> bool {
    SCANF_FUNCS.contains(&name)
}

/// Either printf- or scanf-family: takes/uses a format string.
pub fn is_format_function(name: &str) -> bool {
    is_printf_family(name) || is_scanf_family(name)
}

/// Word-boundary-aware `sizeof` detection over an already-extracted text
/// snippet (not an AST node) -- for the rule files that operate on
/// stringified sub-expressions rather than re-walking the AST. Matches
/// `sizeof` as a whole word so a hypothetical identifier merely containing
/// "sizeof" as a substring doesn't false-match, unlike a bare
/// `contains("sizeof")` check.
pub fn is_sizeof_text(expr: &str) -> bool {
    let bytes = expr.as_bytes();
    let needle = b"sizeof";
    let mut start = 0;
    while let Some(rel) = expr[start..].find("sizeof") {
        let pos = start + rel;
        let before_ok = pos == 0 || !is_ident_byte(bytes[pos - 1]);
        let after = pos + needle.len();
        let after_ok = after >= bytes.len() || !is_ident_byte(bytes[after]);
        if before_ok && after_ok {
            return true;
        }
        start = pos + needle.len();
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heap_allocator_excludes_string_dup() {
        assert!(is_heap_allocator("malloc"));
        assert!(is_heap_allocator("aligned_alloc"));
        assert!(!is_heap_allocator("strdup"));
    }

    #[test]
    fn allocator_call_includes_string_dup() {
        assert!(is_allocator_call("strdup"));
        assert!(is_allocator_call("strndup"));
        assert!(is_allocator_call("calloc"));
        assert!(!is_allocator_call("free"));
    }

    #[test]
    fn printf_family_includes_wide_and_fd_variants() {
        assert!(is_printf_family("dprintf"));
        assert!(is_printf_family("wprintf"));
        assert!(!is_printf_family("puts"));
    }

    #[test]
    fn sizeof_text_is_word_boundary_aware() {
        assert!(is_sizeof_text("sizeof(int)"));
        assert!(is_sizeof_text("n * sizeof x"));
        assert!(!is_sizeof_text("mysizeof(int)"));
        assert!(!is_sizeof_text("sizeofx"));
    }
}
