//! Project-relevance detection (task 216).
//!
//! Detects whole rule *classes* that are categorically inapplicable to a
//! codebase (no threading API in sight => CON* concurrency rules cannot
//! fire; no Win32 API in sight => WIN* rules cannot fire) and generates a
//! manifest override that disables exactly those classes, with an inline
//! rationale comment per disabled rule. This is a relevance/applicability
//! gate, not a false-positive suppressor: genuine analyzer FPs on rules that
//! stay enabled are still measured normally (see
//! docs/design/project-relevance-gating.md, memory
//! fn-focus-vs-perproject-disable).
//!
//! Conservative by construction: every dimension is "any evidence found =>
//! stays enabled". A file that fails to parse contributes no evidence either
//! way but does not flip a signal to "irrelevant" on its own.

use crate::manifest::RuleManifest;
use crate::parser::CParser;
use lang_parsing_substrate::{detect_min_c_standard, query, CStandard};

use anyhow::Result;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// CON0x/CON3x concurrency rules: inapplicable with no threading API in the
/// scanned corpus.
pub const CON_RULE_IDS: &[&str] = &[
    "CON01-C", "CON02-C", "CON03-C", "CON04-C", "CON05-C", "CON06-C", "CON07-C", "CON08-C",
    "CON09-C", "CON30-C", "CON31-C", "CON32-C", "CON33-C", "CON34-C", "CON35-C", "CON36-C",
    "CON37-C", "CON38-C", "CON39-C", "CON40-C", "CON41-C", "CON43-C", "CON50-C",
];

/// WIN* rules: inapplicable with no Win32 API in the scanned corpus.
pub const WIN_RULE_IDS: &[&str] = &[
    "WIN00-C", "WIN01-C", "WIN02-C", "WIN03-C", "WIN04-C", "WIN30-C",
];

/// Rules whose implementation mixes C11-specific logic with plain-C99 logic
/// in the same rule file. `max_c_standard`/`has_annex_k` are surfaced as a
/// reporting-only comment on these — auto-*gating* them is deferred (see
/// design doc §5 and task 300's audit below): none of the 8 qualify for
/// whole-rule auto-disable.
///
/// Task 300 did the per-rule audit design doc §5 called for, across all 14
/// rules originally in this list, and found:
///
/// - **CON02-C, CON03-C, CON07-C, CON31-C, CON32-C, CON33-C** (kept):
///   genuinely mixed, but C11 primitives (`mtx_t`/`mtx_lock`/`mtx_destroy`/
///   `_Atomic`/`atomic_*`) appear only as one of *several* recognized
///   compliant escape hatches alongside their POSIX-pthread equivalents,
///   never as a firing precondition — the dominant, real-world-reachable
///   trigger for every one of these 6 is plain C89/C99/POSIX (a bare
///   `volatile int flag`, a `pthread_mutex_destroy` in a thread function,
///   an unprotected bit-field access, a `strtok`/`asctime` call). Disabling
///   any of them on "no C11 evidence" would silently drop that dominant
///   signal, not just a minor C11 corner.
/// - **EXP44-C, FIO11-C** (kept): also genuinely mixed, but the opposite
///   risk — their C11/Annex-K-specific branches are *already* self-limiting
///   (`EXP44-C` only enters its `_Alignof`/`_Generic` checks when the AST
///   node kind literally contains "alignof"/"generic", which cannot exist
///   without that exact C11 syntax present; `FIO11-C`'s `fopen_s` check is
///   a plain name-equality that just never matches when absent). Nothing
///   to gain from disabling either — their dominant value is the plain
///   `sizeof`-side-effect / `fopen()`-mode-string check, unrelated to C11.
/// - **ENV31-C, API04-C, API07-C, PRE30-C, PRE31-C** (removed from this
///   list, task 300): audit found these were misclassified in the
///   original task 216 v1 list — each one's *only* C11/Annex-K mention is
///   inside a remediation *suggestion string* (e.g. "use `strcpy_s()`
///   instead") or a single exemption check, never inside the rule's actual
///   firing/detection logic. None of these five have a real C11-tangled
///   code path to report on at all.
/// - **PRE04-C** (removed from this list, task 300): a different kind of
///   category mismatch, not a coverage-loss risk — it flags a *local*
///   header reusing a standard-library basename (its 28-name list happens
///   to include 4 C11 names: `stdatomic.h`/`stdalign.h`/`threads.h`/
///   `uchar.h`). The signal this needs is "does the standard library
///   define this name", which is fixed by the standard's existence, not by
///   whether *this project's own code* has reached C11 — a strict-C99
///   project can still ship a colliding local `threads.h`. Gating this
///   rule on corpus C11-syntax-usage evidence is simply the wrong
///   dimension, so there is no "detected: standard=X" comment worth
///   attaching to it.
pub const C11_TANGLED_RULE_IDS: &[&str] = &[
    "CON02-C", "CON03-C", "CON07-C", "CON31-C", "CON32-C", "CON33-C", "EXP44-C", "FIO11-C",
];

/// Project-wide relevance signals, detected once over the whole scanned
/// corpus (input path + `-d` directories).
#[derive(Debug, Default, Clone)]
pub struct ProjectProfile {
    /// Any evidence of POSIX threads (`pthread.h`, `pthread_*`) or C11
    /// threads (`threads.h`, `thrd_*`/`mtx_*`/`cnd_*`, `atomic_*`/`_Atomic`).
    pub has_threading: bool,
    /// Any evidence of the Win32 API (`windows.h`/`winsock2.h`/`windef.h`
    /// includes, or `Win32`/`HANDLE`/`LPCSTR` identifiers).
    pub has_windows: bool,
    /// Highest C standard any scanned file's syntax requires, per
    /// `lang_parsing_substrate::detect_min_c_standard`, OR (task 300)
    /// `<stdatomic.h>`/`<threads.h>` inclusion alone. A file can `#include
    /// <stdatomic.h>` and only ever use it through its own typedefs/macros
    /// (e.g. `atomic_bool`, which tree-sitter tokenizes as a plain
    /// `type_identifier` with no distinguishing syntax node), so the header
    /// itself is real evidence `detect_min_c_standard`'s syntax-only walk
    /// cannot see. `None` means no file in the corpus contained a C99+
    /// marker or one of these headers (consistent with C89).
    pub max_c_standard: Option<CStandard>,
    /// Any call to a C11 Annex K bounds-checked function (task 300) --
    /// e.g. `strcpy_s`, `fopen_s`, `memcpy_s`. Matched by exact call-name
    /// against [`ANNEX_K_FUNCTION_NAMES`], never by a `*_s(` text/substring
    /// match, which would false-match a project's own `_s`-suffixed names
    /// (a real risk: `_s` is a common "safe"/"string" suffix convention in
    /// non-Annex-K code).
    pub has_annex_k: bool,
}

const THREADING_INCLUDE_MARKERS: &[&str] = &["pthread.h", "threads.h"];
const THREADING_IDENTIFIER_MARKERS: &[&str] =
    &["pthread_", "mtx_", "cnd_", "thrd_", "atomic_", "_Atomic"];
const WINDOWS_INCLUDE_MARKERS: &[&str] = &["windows.h", "winsock2.h", "windef.h"];
const WINDOWS_IDENTIFIER_MARKERS: &[&str] = &["Win32", "HANDLE", "LPCSTR"];

/// Headers whose mere inclusion is C11 (or later) evidence even with no
/// syntax marker `detect_min_c_standard` can see -- e.g. `<stdatomic.h>`
/// used only through its typedefs (`atomic_bool`, `atomic_int`), which
/// parse as ordinary `type_identifier` nodes with nothing to key a query
/// off. `<threads.h>` overlaps with [`THREADING_INCLUDE_MARKERS`] (both
/// exist because they answer different questions: "is CON* relevant" vs
/// "is this project's language level at least C11").
const C11_HEADER_MARKERS: &[&str] = &["stdatomic.h", "threads.h"];

/// C11 Annex K (K.3) bounds-checked function names. Not exhaustive of
/// every `_s`-suffixed stdlib symbol some platforms add (e.g. `_putenv_s`,
/// `_wputenv_s`, `_vscprintf_s` are MSVCRT extensions, not Annex K), but
/// covers the canonical set defined by the standard itself.
const ANNEX_K_FUNCTION_NAMES: &[&str] = &[
    "tmpfile_s",
    "tmpnam_s",
    "fopen_s",
    "freopen_s",
    "fprintf_s",
    "fscanf_s",
    "printf_s",
    "scanf_s",
    "snprintf_s",
    "sprintf_s",
    "sscanf_s",
    "vfprintf_s",
    "vfscanf_s",
    "vprintf_s",
    "vscanf_s",
    "vsnprintf_s",
    "vsprintf_s",
    "vsscanf_s",
    "gets_s",
    "set_constraint_handler_s",
    "abort_handler_s",
    "ignore_handler_s",
    "getenv_s",
    "bsearch_s",
    "qsort_s",
    "wctomb_s",
    "mbstowcs_s",
    "wcstombs_s",
    "memcpy_s",
    "memmove_s",
    "strcpy_s",
    "strncpy_s",
    "strcat_s",
    "strncat_s",
    "strtok_s",
    "strerror_s",
    "strerrorlen_s",
    "strnlen_s",
    "memset_s",
    "asctime_s",
    "ctime_s",
    "wcscpy_s",
    "wcsncpy_s",
    "wmemcpy_s",
    "wmemmove_s",
    "wcscat_s",
    "wcsncat_s",
    "wcstok_s",
    "wcsnlen_s",
    "wcrtomb_s",
    "mbsrtowcs_s",
    "wcsrtombs_s",
];

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

/// Exact-match scan for Annex K function calls: walks `call_expression`
/// nodes and compares the callee identifier's full text against
/// [`ANNEX_K_FUNCTION_NAMES`]. Deliberately AST-based rather than a `*_s(`
/// substring/regex match -- a project's own function named e.g.
/// `validate_s(...)` or a struct-field-call `obj->encode_s(...)` must never
/// count as Annex-K evidence.
fn contains_annex_k_call(root: tree_sitter::Node, source: &[u8]) -> bool {
    for call in query::find_descendants_of_kind(root, "call_expression") {
        let Some(func) = call.child_by_field_name("function") else {
            continue;
        };
        if func.kind() != "identifier" {
            // Excludes field_expression (obj->method_s()) and any other
            // non-bare-name callee -- Annex K functions are always called
            // as free functions.
            continue;
        }
        let Ok(name) = func.utf8_text(source) else {
            continue;
        };
        if ANNEX_K_FUNCTION_NAMES.contains(&name) {
            return true;
        }
    }
    false
}

/// Walk `dirs` (`.c`/`.h` files only) and detect project-wide relevance
/// signals. A file that fails to parse is skipped (contributes no evidence).
pub fn detect(dirs: &[String]) -> Result<ProjectProfile> {
    let mut profile = ProjectProfile::default();

    let mut files: Vec<PathBuf> = Vec::new();
    for dir in dirs {
        for entry in WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                matches!(
                    e.path().extension().and_then(|ext| ext.to_str()),
                    Some("c") | Some("h")
                )
            })
        {
            files.push(entry.path().to_path_buf());
        }
    }

    for file in &files {
        detect_file(file, &mut profile);
    }

    Ok(profile)
}

fn detect_file(path: &Path, profile: &mut ProjectProfile) {
    let mut parser = match CParser::new() {
        Ok(p) => p,
        Err(_) => return,
    };
    let (tree, source) = match parser.parse_file(&path.to_string_lossy()) {
        Ok(t) => t,
        Err(_) => return,
    };

    if !profile.has_threading
        && (contains_any(&source, THREADING_INCLUDE_MARKERS)
            || contains_any(&source, THREADING_IDENTIFIER_MARKERS))
    {
        profile.has_threading = true;
    }

    if !profile.has_windows
        && (contains_any(&source, WINDOWS_INCLUDE_MARKERS)
            || contains_any(&source, WINDOWS_IDENTIFIER_MARKERS))
    {
        profile.has_windows = true;
    }

    let header_evidence = contains_any(&source, C11_HEADER_MARKERS);
    if let Some(found) = detect_min_c_standard(&tree, source.as_bytes()).or({
        // `detect_min_c_standard` is syntax-only; `<stdatomic.h>`/
        // `<threads.h>` inclusion is C11 evidence it cannot see on its own
        // (see `C11_HEADER_MARKERS`'s doc comment) but carries no stronger
        // claim than "at least C11" -- never promoted to C23.
        header_evidence.then_some(CStandard::C11)
    }) {
        profile.max_c_standard = Some(match profile.max_c_standard {
            Some(existing) if existing >= found => existing,
            _ => found,
        });
    }

    if !profile.has_annex_k && contains_annex_k_call(tree.root_node(), source.as_bytes()) {
        profile.has_annex_k = true;
    }
}

/// Render `base` as a relevance-gated manifest: WIN*/CON* rules the profile
/// says are inapplicable get `enabled = false` with an `# auto: ...`
/// rationale; everything else keeps `base`'s enabled state. Rules in
/// [`C11_TANGLED_RULE_IDS`] get a `# detected: ...` informational comment
/// regardless of enabled state (reporting-only — see module docs).
///
/// Renders TOML directly (not via `toml::to_string`) so per-rule rationale
/// comments survive, matching the hand-authored style of
/// `conf/realworld/*-rules.toml`.
pub fn generate_manifest_toml(base: &RuleManifest, profile: &ProjectProfile) -> String {
    let mut out = String::new();

    out.push_str("[metadata]\n");
    out.push_str(&format!("name = {:?}\n", base.metadata.name));
    out.push_str(&format!("version = {:?}\n", base.metadata.version));
    let description = format!(
        "{} (relevance-gated by sqc --detect-relevance: threading={}, windows={})",
        base.metadata
            .description
            .clone()
            .unwrap_or_else(|| "Auto-generated rules manifest".to_string()),
        profile.has_threading,
        profile.has_windows,
    );
    out.push_str(&format!("description = {:?}\n", description));
    out.push_str(&format!(
        "cert_version = {:?}\n",
        base.metadata.cert_version
    ));

    let mut rule_ids: Vec<&String> = base
        .rules
        .cert_c
        .keys()
        .chain(base.rules.brules.keys())
        .collect();
    rule_ids.sort();
    rule_ids.dedup();

    for rule_id in rule_ids {
        let Some(config) = base.get_rule(rule_id) else {
            continue;
        };

        let (enabled, comment) = gate_rule(rule_id, config.enabled, profile);

        out.push_str("\n[rules.cert_c.");
        out.push_str(rule_id);
        out.push_str("]\n");
        out.push_str("enabled = ");
        out.push_str(if enabled { "true" } else { "false" });
        if let Some(comment) = comment {
            out.push_str("  # ");
            out.push_str(&comment);
        }
        out.push('\n');
    }

    out
}

fn gate_rule(
    rule_id: &str,
    base_enabled: bool,
    profile: &ProjectProfile,
) -> (bool, Option<String>) {
    if base_enabled && CON_RULE_IDS.contains(&rule_id) && !profile.has_threading {
        return (
            false,
            Some(
                "auto: no pthread/threads.h/atomic usage detected in corpus (task 216)".to_string(),
            ),
        );
    }

    if base_enabled && WIN_RULE_IDS.contains(&rule_id) && !profile.has_windows {
        return (
            false,
            Some("auto: no Win32 API usage detected in corpus (task 216)".to_string()),
        );
    }

    if C11_TANGLED_RULE_IDS.contains(&rule_id) {
        let standard = match profile.max_c_standard {
            Some(CStandard::C99) => "C99",
            Some(CStandard::C11) => "C11",
            Some(CStandard::C23) => "C23",
            None => "<=C99",
        };
        return (
            base_enabled,
            Some(format!(
                "detected: corpus max C standard = {standard}, Annex-K calls = {} \
                 (reporting-only, task 300's per-rule audit found none of this group \
                 safe to auto-gate — see C11_TANGLED_RULE_IDS doc comment)",
                profile.has_annex_k
            )),
        );
    }

    (base_enabled, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_file(dir: &Path, name: &str, contents: &str) {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
    }

    #[test]
    fn detects_no_threading_no_windows_c99_corpus() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "a.c",
            "int add(int a, int b) { return a + b; }\n",
        );
        let profile = detect(&[dir.path().to_string_lossy().to_string()]).unwrap();
        assert!(!profile.has_threading);
        assert!(!profile.has_windows);
        assert_eq!(profile.max_c_standard, None);
    }

    #[test]
    fn detects_pthread_usage_via_include() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "a.c", "#include <pthread.h>\nvoid f(void) {}\n");
        let profile = detect(&[dir.path().to_string_lossy().to_string()]).unwrap();
        assert!(profile.has_threading);
    }

    #[test]
    fn detects_windows_usage_via_include() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "a.c", "#include <windows.h>\nvoid f(void) {}\n");
        let profile = detect(&[dir.path().to_string_lossy().to_string()]).unwrap();
        assert!(profile.has_windows);
    }

    #[test]
    fn detects_c11_generic_marker() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "a.c",
            "int f(int x) { return _Generic(x, int: 1, default: 0); }\n",
        );
        let profile = detect(&[dir.path().to_string_lossy().to_string()]).unwrap();
        assert_eq!(profile.max_c_standard, Some(CStandard::C11));
    }

    #[test]
    fn detects_c11_via_stdatomic_header_alone() {
        // atomic_bool/atomic_int parse as plain type_identifier nodes --
        // detect_min_c_standard's syntax-only walk can't see them (task
        // 300 gap 2a), so the header itself must be the evidence.
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "a.c",
            "#include <stdatomic.h>\natomic_bool ready;\n",
        );
        let profile = detect(&[dir.path().to_string_lossy().to_string()]).unwrap();
        assert_eq!(profile.max_c_standard, Some(CStandard::C11));
    }

    #[test]
    fn does_not_promote_standard_without_c11_header_or_syntax() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "a.c", "#include <stdio.h>\nvoid f(void) {}\n");
        let profile = detect(&[dir.path().to_string_lossy().to_string()]).unwrap();
        assert_eq!(profile.max_c_standard, None);
    }

    #[test]
    fn detects_annex_k_call_by_exact_name() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "a.c",
            "void f(char *dst, const char *src) { strcpy_s(dst, 10, src); }\n",
        );
        let profile = detect(&[dir.path().to_string_lossy().to_string()]).unwrap();
        assert!(profile.has_annex_k);
    }

    #[test]
    fn does_not_false_match_user_defined_s_suffixed_function() {
        // task 300 gap 2b: a project's own `_s`-suffixed name (not one of
        // the real Annex K functions) must never count as evidence -- this
        // is exactly why detection is an exact AST call-name match, not a
        // `*_s(` text/substring scan.
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "a.c",
            "int validate_s(int x) { return x; }\nint g(void) { return validate_s(1); }\n",
        );
        let profile = detect(&[dir.path().to_string_lossy().to_string()]).unwrap();
        assert!(!profile.has_annex_k);
    }

    #[test]
    fn does_not_false_match_s_suffixed_method_call() {
        // obj->encode_s(...) / obj.encode_s(...) is a field_expression
        // callee, not a bare identifier -- Annex K functions are always
        // called as free functions, so this must not match either.
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "a.c",
            "struct Ops { int (*encode_s)(int); };\nint g(struct Ops *o) { return o->encode_s(1); }\n",
        );
        let profile = detect(&[dir.path().to_string_lossy().to_string()]).unwrap();
        assert!(!profile.has_annex_k);
    }

    #[test]
    fn c11_tangled_list_excludes_rules_task_300_found_misclassified() {
        // ENV31-C/API04-C/API07-C/PRE30-C/PRE31-C's only C11/Annex-K
        // mention was in remediation-suggestion text, never in detection
        // logic; PRE04-C's gating axis (standard-library header-name
        // collision) is a category mismatch with corpus C11-usage
        // evidence. None belong in the reporting list any more.
        for id in [
            "ENV31-C", "API04-C", "API07-C", "PRE04-C", "PRE30-C", "PRE31-C",
        ] {
            assert!(
                !C11_TANGLED_RULE_IDS.contains(&id),
                "{id} should have been removed from C11_TANGLED_RULE_IDS"
            );
        }
        for id in [
            "CON02-C", "CON03-C", "CON07-C", "CON31-C", "CON32-C", "CON33-C", "EXP44-C", "FIO11-C",
        ] {
            assert!(
                C11_TANGLED_RULE_IDS.contains(&id),
                "{id} should still be in C11_TANGLED_RULE_IDS"
            );
        }
    }

    fn base_manifest() -> RuleManifest {
        RuleManifest::load("rules_templates/rules-all.toml").unwrap()
    }

    #[test]
    fn generate_disables_con_and_win_when_absent() {
        let manifest = base_manifest();
        let profile = ProjectProfile {
            has_threading: false,
            has_windows: false,
            max_c_standard: None,
            has_annex_k: false,
        };
        let toml = generate_manifest_toml(&manifest, &profile);
        for id in CON_RULE_IDS {
            assert!(
                toml.contains(&format!("[rules.cert_c.{id}]\nenabled = false")),
                "expected {id} disabled:\n{toml}"
            );
        }
        for id in WIN_RULE_IDS {
            assert!(
                toml.contains(&format!("[rules.cert_c.{id}]\nenabled = false")),
                "expected {id} disabled:\n{toml}"
            );
        }
        // Non-CON/WIN rules stay enabled per the base manifest.
        assert!(toml.contains("[rules.cert_c.ARR30-C]\nenabled = true"));
    }

    #[test]
    fn generate_keeps_con_and_win_when_present() {
        let manifest = base_manifest();
        let profile = ProjectProfile {
            has_threading: true,
            has_windows: true,
            max_c_standard: None,
            has_annex_k: false,
        };
        let toml = generate_manifest_toml(&manifest, &profile);
        for id in CON_RULE_IDS {
            assert!(toml.contains(&format!("[rules.cert_c.{id}]\nenabled = true")));
        }
        for id in WIN_RULE_IDS {
            assert!(toml.contains(&format!("[rules.cert_c.{id}]\nenabled = true")));
        }
    }

    #[test]
    fn generate_never_disables_rule_the_base_already_disabled_via_gating_comment() {
        // A rule the base manifest disabled for unrelated reasons must not
        // get relabelled with an "auto:" relevance rationale -- gating only
        // ever turns an enabled rule off, never re-explains an existing off.
        let mut manifest = base_manifest();
        manifest.get_rule_mut("CON01-C").unwrap().enabled = false;
        let profile = ProjectProfile {
            has_threading: false,
            has_windows: false,
            max_c_standard: None,
            has_annex_k: false,
        };
        let toml = generate_manifest_toml(&manifest, &profile);
        assert!(toml.contains("[rules.cert_c.CON01-C]\nenabled = false\n"));
        assert!(!toml.contains("CON01-C]\nenabled = false  # auto"));
    }
}
