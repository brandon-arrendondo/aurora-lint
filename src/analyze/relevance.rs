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
use lang_parsing_substrate::{detect_min_c_standard, CStandard};

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
/// in the same rule file. `max_c_standard` is surfaced as a reporting-only
/// comment on these — auto-*gating* them is deferred (see design doc §5):
/// the C11-only code path inside each one needs a per-rule audit before a
/// manifest-level toggle is safe.
pub const C11_TANGLED_RULE_IDS: &[&str] = &[
    "CON02-C", "CON03-C", "CON07-C", "CON31-C", "CON32-C", "CON33-C", "ENV31-C", "API04-C",
    "API07-C", "PRE04-C", "PRE30-C", "PRE31-C", "EXP44-C", "FIO11-C",
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
    /// `lang_parsing_substrate::detect_min_c_standard`. `None` means no file
    /// in the corpus contained a C99+ marker (consistent with C89).
    pub max_c_standard: Option<CStandard>,
}

const THREADING_INCLUDE_MARKERS: &[&str] = &["pthread.h", "threads.h"];
const THREADING_IDENTIFIER_MARKERS: &[&str] =
    &["pthread_", "mtx_", "cnd_", "thrd_", "atomic_", "_Atomic"];
const WINDOWS_INCLUDE_MARKERS: &[&str] = &["windows.h", "winsock2.h", "windef.h"];
const WINDOWS_IDENTIFIER_MARKERS: &[&str] = &["Win32", "HANDLE", "LPCSTR"];

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
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

    if let Some(found) = detect_min_c_standard(&tree, source.as_bytes()) {
        profile.max_c_standard = Some(match profile.max_c_standard {
            Some(existing) if existing >= found => existing,
            _ => found,
        });
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
                "detected: corpus max C standard = {standard} (reporting-only, task 216 \
                 does not auto-gate C11/Annex-K sub-behavior yet)"
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
        };
        let toml = generate_manifest_toml(&manifest, &profile);
        assert!(toml.contains("[rules.cert_c.CON01-C]\nenabled = false\n"));
        assert!(!toml.contains("CON01-C]\nenabled = false  # auto"));
    }
}
