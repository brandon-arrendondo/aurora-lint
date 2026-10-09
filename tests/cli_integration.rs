//! CLI integration tests for aurora-lint.
//!
//! These tests invoke the aurora-lint binary as a subprocess and verify:
//! - Export formats (JSON, CSV, SARIF)
//! - Exit codes (--fail-on-violation, --fail-on-severity)
//! - Filtering (--rules, --min-severity)
//! - Prescan caching (--save-prescan, --load-prescan)
//! - Suppression (inline comments and TOML file)
//! - Cross-file analysis (-d flag)
//! - Diff-only mode (--diff flag)
//! - Policy and environment settings (--profile, --set, --list-options)

use std::path::PathBuf;
use std::process::Command;

fn aurora_lint_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aurora-lint"))
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cli")
}

fn manifest_msc04() -> PathBuf {
    fixtures().join("manifest_msc04.toml")
}

fn manifest_dcl31() -> PathBuf {
    fixtures().join("manifest_dcl31.toml")
}

/// Run aurora-lint with given args, return (exit_code, stdout, stderr).
fn run_aurora_lint(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(aurora_lint_bin())
        .args(args)
        .output()
        .expect("failed to execute aurora-lint");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

/// Remove any git environment variables inherited from the parent process.
///
/// When the test suite runs from inside a git hook (e.g. the pre-commit hook
/// via `cargo llvm-cov`), `git commit` exports `GIT_DIR` and `GIT_INDEX_FILE`
/// into the environment. Subprocesses spawned with `Command` inherit them, so a
/// `git add` run with `current_dir(temp_repo)` would still mutate the *outer*
/// repo's commit index instead of the temp repo's — leaving a stray `clean.c`
/// entry that points at a blob in the temp object store and corrupting the
/// outer commit ("invalid object … Error building trees"). Scrub these so temp
/// repos are fully isolated.
fn scrub_git_env(cmd: &mut Command) -> &mut Command {
    for var in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_PREFIX",
        "GIT_CONFIG_PARAMETERS",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

/// Run a `git` subcommand scoped to `repo_dir` with the inherited git
/// environment scrubbed (see [`scrub_git_env`]).
fn git_in(repo_dir: &std::path::Path, args: &[&str]) {
    let status = scrub_git_env(&mut Command::new("git"))
        .args(args)
        .current_dir(repo_dir)
        .output()
        .expect("failed to execute git");
    assert!(
        status.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&status.stderr)
    );
}

// ─── Export formats ──────────────────────────────────────────────────────────

#[test]
fn removed_per_rule_keys_warn_and_still_load() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, stderr) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        fixtures()
            .join("manifest_removed_keys.toml")
            .to_str()
            .unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    for key in ["category", "cert_id", "parameters"] {
        assert!(
            stderr.contains(&format!("Warning: ignoring `{key}` for rule MSC04-C")),
            "expected a warning naming `{key}` and the rule, stderr: {stderr}"
        );
    }

    // The rest of the manifest still applies: MSC04-C runs and reports.
    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert_eq!(violations.len(), 1);
}

#[test]
fn export_json_structure() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert_eq!(violations.len(), 1);

    let v = &violations[0];
    assert_eq!(v["tool"], "aurora-lint");
    assert_eq!(v["rule_id"], "MSC04-C");
    assert_eq!(v["line"], 1);
    assert_eq!(v["severity"], "Medium");
    assert!(v["message"].as_str().unwrap().contains("infinite"));
}

#[test]
fn export_json_empty_for_clean_file() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("clean.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(violations.is_empty());
}

#[test]
fn export_rejects_spreadsheet_formats() {
    // CSV/XLSX are derived from SARIF by scripts/sarif_convert.py, not
    // written by the tool; the error has to say so rather than silently
    // falling back to some other format.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.csv");
    let (code, _, stderr) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_ne!(code, 0);
    assert!(stderr.contains("sarif_convert.py"), "stderr: {stderr}");
    assert!(!out.exists());
}

#[test]
fn export_sarif_structure() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.sarif");
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(sarif["version"], "2.1.0");
    assert!(sarif["$schema"].as_str().unwrap().contains("sarif"));

    let run = &sarif["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "aurora-lint");

    let results = &run["results"];
    assert_eq!(results.as_array().unwrap().len(), 1);
    assert_eq!(results[0]["ruleId"], "MSC04-C");

    // The report stands alone: the rule's own description (not a finding's
    // message), the flagged source line, and a content hash of its file.
    let rule = &run["tool"]["driver"]["rules"][0];
    assert_ne!(
        rule["shortDescription"]["text"],
        results[0]["message"]["text"]
    );
    assert_ne!(rule["shortDescription"]["text"], "Unknown rule");

    let location = &results[0]["locations"][0]["physicalLocation"];
    let source = std::fs::read_to_string(fixtures().join("violation.c")).unwrap();
    assert_eq!(
        location["region"]["snippet"]["text"],
        source.lines().next().unwrap().trim()
    );
    let index = location["artifactLocation"]["index"].as_u64().unwrap() as usize;
    let sha = run["artifacts"][index]["hashes"]["sha-256"]
        .as_str()
        .unwrap();
    assert_eq!(sha.len(), 64);
}

/// A header the scan cannot find is loud: one stderr line by default, every
/// row with -v, a SARIF note that leaves the run successful, and the whole
/// report with --report-headers. None of it changes a finding.
#[test]
fn missing_headers_are_reported_on_stderr_in_sarif_and_on_request() {
    let dir = tempfile::tempdir().unwrap();
    let proj = dir.path().join("proj");
    let sys = dir.path().join("sys");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&sys).unwrap();
    std::fs::write(sys.join("lib.h"), "int lib_init(void);\n").unwrap();
    std::fs::write(
        proj.join("main.c"),
        "#include <lib.h>\n#include <missing_dep.h>\nint main(void) { return lib_init(); }\n",
    )
    .unwrap();
    let sarif = dir.path().join("out.sarif");
    let report = dir.path().join("headers.json");
    let manifest = manifest_msc04();
    let base = [
        proj.to_str().unwrap(),
        "-d",
        proj.to_str().unwrap(),
        "-I",
        sys.to_str().unwrap(),
        "-m",
        manifest.to_str().unwrap(),
    ];

    let (code, _, stderr) = run_aurora_lint(&base);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stderr.contains(
            "Headers: 1 #include'd header(s) not found (1 named by project files, 0 only by \
             system headers): missing_dep.h. Declarations and macros they would supply were \
             not seen"
        ),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("unresolved #include"),
        "rows only with -v: {stderr}"
    );

    let mut args = base.to_vec();
    args.extend([
        "-v",
        "-e",
        sarif.to_str().unwrap(),
        "--report-headers",
        report.to_str().unwrap(),
    ]);
    let (code, _, stderr) = run_aurora_lint(&args);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stderr.contains("unresolved #include <missing_dep.h> from "),
        "{stderr}"
    );

    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sarif).unwrap()).unwrap();
    let run = &sarif["runs"][0];
    let invocation = &run["invocations"][0];
    assert_eq!(invocation["executionSuccessful"], true);
    let notes = invocation["toolExecutionNotifications"].as_array().unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0]["level"], "note");
    assert_eq!(
        notes[0]["descriptor"]["id"],
        "aurora-lint/headers-not-found"
    );
    let headers = &run["properties"]["aurora-lint/headers"];
    assert_eq!(headers["unresolved"][0]["spelling"], "missing_dep.h");
    assert_eq!(headers["outsideHeaderCount"], 1);

    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(report["unresolved"][0]["line"], 2);
    assert_eq!(
        report["outside_headers"][0]["sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
}

/// A finding of a rule that reads header-supplied facts, in a file whose
/// includes reach a header a project file names and the scan could not find,
/// says it may depend on it; one whose project includes all resolved carries
/// no marker, even though a system header it includes names a `bits/` header
/// the scan could not find either. That miss is counted apart on stderr.
#[test]
fn a_finding_that_may_depend_on_a_missing_header_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let proj = dir.path().join("proj");
    let sys = dir.path().join("sys");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&sys).unwrap();
    std::fs::write(
        sys.join("lib.h"),
        "#include <bits/libc-header-start.h>\nint lib_init(void);\n",
    )
    .unwrap();
    std::fs::write(
        proj.join("a.c"),
        "#include <lib.h>\n#include <missing_dep.h>\n\
         int main(void) { lib_init(); return dep_init(); }\n",
    )
    .unwrap();
    std::fs::write(
        proj.join("b.c"),
        "#include <lib.h>\nint b(void) { return other_undeclared(); }\n",
    )
    .unwrap();
    let manifest = manifest_dcl31();
    let json = dir.path().join("out.json");
    let sarif = dir.path().join("out.sarif");
    for out in [&json, &sarif] {
        let (code, _, stderr) = run_aurora_lint(&[
            proj.to_str().unwrap(),
            "-d",
            proj.to_str().unwrap(),
            "-I",
            sys.to_str().unwrap(),
            "-m",
            manifest.to_str().unwrap(),
            "-e",
            out.to_str().unwrap(),
        ]);
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(
            stderr.contains(
                "Headers: 1 #include'd header(s) not found (1 named by project files, 0 only by \
                 system headers): missing_dep.h."
            ),
            "stderr: {stderr}"
        );
        assert!(
            stderr.contains(
                "Not counted: 1 from the compiler's built-in and multiarch directories, which \
                 the scan searches only with --system-includes (bits/libc-header-start.h)."
            ),
            "stderr: {stderr}"
        );
    }

    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    let marker = |file: &str| {
        let row = rows
            .iter()
            .find(|r| r["file"].as_str().unwrap().ends_with(file))
            .unwrap_or_else(|| panic!("no finding in {file}: {rows:?}"));
        assert_eq!(row["rule_id"], "DCL31-C");
        row.get("missing_headers").cloned()
    };
    assert_eq!(marker("a.c"), Some(serde_json::json!(["missing_dep.h"])));
    assert_eq!(marker("b.c"), None);

    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sarif).unwrap()).unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    let a = results
        .iter()
        .find(|r| {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap()
                .ends_with("a.c")
        })
        .unwrap();
    assert_eq!(
        a["properties"]["missingHeaders"],
        serde_json::json!(["missing_dep.h"])
    );
}

/// A finding whose line spells a macro only a header outside the project
/// defines names that macro and the header (the libtomcrypt `XFREE` shape).
#[test]
fn a_finding_names_the_outside_header_a_macro_on_its_line_came_from() {
    let dir = tempfile::tempdir().unwrap();
    let proj = dir.path().join("proj");
    let sys = dir.path().join("sys");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&sys).unwrap();
    std::fs::write(sys.join("tomcustom.h"), "#define XFREE free\n").unwrap();
    std::fs::write(
        proj.join("glue.c"),
        "#include <stdlib.h>\n#include <tomcustom.h>\n\
         void release(void) {\n    char *p = malloc(4);\n    XFREE(p);\n    XFREE(p);\n}\n",
    )
    .unwrap();
    let json = dir.path().join("out.json");
    let (code, stdout, stderr) = run_aurora_lint(&[
        proj.to_str().unwrap(),
        "-d",
        proj.to_str().unwrap(),
        "-I",
        sys.to_str().unwrap(),
        "--rules",
        "MEM30-C",
        "-v",
        "-e",
        json.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let header = std::fs::canonicalize(sys.join("tomcustom.h")).unwrap();
    let expected = format!("XFREE ({})", header.display());
    assert!(
        stdout.contains(&format!(
            "note: uses macro(s) defined only outside the project: {expected}"
        )),
        "stdout: {stdout}"
    );
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    let double_free = rows
        .iter()
        .find(|r| r["rule_id"] == "MEM30-C" && r["line"] == 6)
        .unwrap_or_else(|| panic!("no MEM30-C at line 6: {rows:?}"));
    assert_eq!(double_free["harvested_from"], serde_json::json!([expected]));
}

// ─── Policy and environment settings ─────────────────────────────────────────

/// Export `violation.c` as SARIF with `args` appended; return the run's
/// recorded settings block.
fn sarif_settings(manifest: &std::path::Path, args: &[&str]) -> serde_json::Value {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.sarif");
    let mut all = vec![
        fixtures().join("violation.c").to_str().unwrap().to_string(),
        "-m".to_string(),
        manifest.to_str().unwrap().to_string(),
        "-e".to_string(),
        out.to_str().unwrap().to_string(),
    ];
    all.extend(args.iter().map(|a| a.to_string()));
    let refs: Vec<&str> = all.iter().map(String::as_str).collect();
    let (code, _, stderr) = run_aurora_lint(&refs);
    assert_eq!(code, 0, "stderr: {stderr}");
    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    sarif["runs"][0]["properties"]["aurora-lint/settings"].clone()
}

#[test]
fn sarif_records_default_settings() {
    let s = sarif_settings(&manifest_msc04(), &[]);
    assert_eq!(s["preset"], "default");
    assert_eq!(s["policy"], "default");
    assert_eq!(s["environment"], "hosted");
    assert_eq!(s["libc"], "iso-posix");
    assert_eq!(s["options"]["assert_is_guard"], true);
    assert_eq!(s["options"]["free_null_is_noop"], true);
    // The hash names the settings: 64 hex characters, stable for equal
    // settings, different for different ones.
    let hash = s["hash"].as_str().unwrap();
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(sarif_settings(&manifest_msc04(), &[])["hash"], s["hash"]);
    assert_ne!(
        sarif_settings(&manifest_msc04(), &["--profile", "strict"])["hash"],
        s["hash"]
    );
}

#[test]
fn the_pedantic_preset_is_named_in_the_settings_and_the_banner() {
    let s = sarif_settings(&manifest_msc04(), &["--profile", "pedantic"]);
    assert_eq!(s["preset"], "pedantic");
    assert_eq!(s["policy"], "pedantic");
    assert_eq!(s["environment"], "hosted");
    assert_eq!(s["libc"], serde_json::Value::Null);
    assert_eq!(s["libc_declared"], false);
    assert_eq!(s["options"]["trust_noreturn_keyword"], false);
    assert_ne!(
        s["hash"],
        sarif_settings(&manifest_msc04(), &["--profile", "strict"])["hash"]
    );
    let (code, stdout, stderr) = run_aurora_lint(&[
        fixtures().join("repeated_deref.c").to_str().unwrap(),
        "-m",
        fixtures().join("manifest_exp34.toml").to_str().unwrap(),
        "--profile",
        "pedantic",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("Settings: pedantic preset (policy=pedantic, environment=hosted)"),
        "{stdout}"
    );
    // No library is declared: the scan names the key and the enabled rules
    // whose findings depend on one.
    assert!(
        stderr.contains("warning: the pedantic preset trusts only a declared C library"),
        "{stderr}"
    );
    assert!(stderr.contains("[environment] libc"), "{stderr}");
    assert!(
        stderr.contains("disable the rules whose findings depend on it: EXP34-C."),
        "{stderr}"
    );
    let (code, stdout, stderr) = run_aurora_lint(&[
        "--check-config",
        "-m",
        fixtures().join("manifest_exp34.toml").to_str().unwrap(),
        "--profile",
        "pedantic",
    ]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout.trim(), "configuration ok");
    assert!(
        stderr.starts_with("warning: the pedantic preset"),
        "{stderr}"
    );
    let (code, _stdout, stderr) = run_aurora_lint(&[
        "--check-config",
        "-m",
        fixtures().join("manifest_exp34.toml").to_str().unwrap(),
        "--profile",
        "pedantic",
        "--libc",
        "newlib-nano",
    ]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
}

#[test]
fn sarif_records_strict_preset_from_cli() {
    let s = sarif_settings(&manifest_msc04(), &["--profile", "strict"]);
    assert_eq!(s["preset"], "strict");
    assert_eq!(s["environment"], "hosted");
    assert_eq!(s["libc"], "iso-posix");
    assert_eq!(s["options"]["assert_is_guard"], false);
    assert_eq!(s["options"]["trust_noreturn_keyword"], true);
    assert_eq!(s["options"]["free_null_is_noop"], true);
    assert_eq!(s["options"]["main_argv_guarantees"], true);
}

#[test]
fn manifest_settings_apply_and_name_no_preset_when_overridden() {
    let manifest = fixtures().join("manifest_msc04_strict_newlib.toml");
    let s = sarif_settings(&manifest, &[]);
    // The strict preset on newlib, whose documented contracts are trusted,
    // with one startup guarantee withdrawn: not the preset any more.
    assert_eq!(s["preset"], serde_json::Value::Null);
    assert_eq!(s["policy"], "strict");
    assert_eq!(s["libc"], "newlib");
    assert_eq!(s["options"]["free_null_is_noop"], true);
    assert_eq!(s["options"]["main_argv_guarantees"], true);
    assert_eq!(s["options"]["static_zero_init"], false);
}

#[test]
fn cli_profile_restarts_from_the_preset() {
    let manifest = fixtures().join("manifest_msc04_strict_newlib.toml");
    let s = sarif_settings(&manifest, &["--profile", "default"]);
    assert_eq!(s["preset"], "default");
    let s = sarif_settings(&manifest, &["--set", "static_zero_init=true"]);
    assert_eq!(s["options"]["static_zero_init"], true);
    assert_eq!(s["libc"], "newlib");
}

#[test]
fn list_rules_lists_shipped_rules_then_removed_ones() {
    let (code, stdout, _) = run_aurora_lint(&["--list-rules"]);
    assert_eq!(code, 0);
    assert!(stdout.starts_with("Rules ("), "stdout: {stdout}");
    assert!(stdout.contains("  ARR30-C    on "), "stdout: {stdout}");
    assert!(stdout.contains("\nRemoved rules"), "stdout: {stdout}");

    let (code, stdout, _) = run_aurora_lint(&["--list-rules", "json"]);
    assert_eq!(code, 0);
    let listing: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(listing["rules"].as_array().unwrap().len() > 300);
    assert!(listing["removed"].is_array());
}

#[test]
fn unknown_or_misplaced_option_is_refused() {
    let (code, _, stderr) = run_aurora_lint(&["--list-options", "--set", "no_such=true"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("unknown option 'no_such'"),
        "stderr: {stderr}"
    );

    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("m.toml");
    std::fs::write(
        &manifest,
        "[metadata]\nname = \"m\"\nversion = \"1\"\ncert_version = \"2016\"\n\
         [rules.cert_c]\n[environment.overrides]\nassert_is_guard = false\n",
    )
    .unwrap();
    let (code, _, stderr) = run_aurora_lint(&["--list-options", "-m", manifest.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("does not belong in [environment.overrides]"),
        "stderr: {stderr}"
    );
}

#[test]
fn first_site_only_reports_a_dependent_chain_once() {
    // `p` may be null and is dereferenced unchecked on four lines, all
    // depending on one missing check.
    let count = |preset: &str| {
        let (code, stdout, stderr) = run_aurora_lint(&[
            fixtures().join("repeated_deref.c").to_str().unwrap(),
            "-m",
            fixtures().join("manifest_exp34.toml").to_str().unwrap(),
            "--profile",
            preset,
        ]);
        assert_eq!(code, 0, "stderr: {stderr}");
        stdout.matches("EXP34-C:").count()
    };
    assert_eq!(count("default"), 1);
    assert_eq!(count("strict"), 4);
}

#[test]
fn options_doc_matches_the_table() {
    let (code, stdout, stderr) = run_aurora_lint(&["--list-options", "rst"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let committed =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/options.rst"))
            .unwrap();
    assert_eq!(
        committed, stdout,
        "docs/options.rst is stale: regenerate it with \
         `aurora-lint --list-options rst > docs/options.rst`"
    );
}

#[test]
fn list_options_json_names_every_option_under_every_preset() {
    let (code, stdout, _) = run_aurora_lint(&["--list-options", "json"]);
    assert_eq!(code, 0);
    let listing: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let options = listing["options"].as_array().unwrap();
    assert!(!options.is_empty());
    for o in options {
        for preset in ["default", "strict", "pedantic"] {
            assert!(o[preset].is_boolean(), "{preset}: {o}");
        }
        assert!(!o["basis"].as_str().unwrap().is_empty(), "{o}");
    }
}

// ─── Exit codes ──────────────────────────────────────────────────────────────

#[test]
fn exit_code_zero_no_violations() {
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("clean.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
}

#[test]
fn exit_code_zero_without_fail_flag() {
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
    ]);
    // Without --fail-on-violation, violations don't cause exit 1
    assert_eq!(code, 0);
}

#[test]
fn fail_on_violation_exits_one() {
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "--fail-on-violation",
    ]);
    assert_eq!(code, 1);
}

#[test]
fn fail_on_violation_exits_zero_when_clean() {
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("clean.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "--fail-on-violation",
    ]);
    assert_eq!(code, 0);
}

#[test]
fn fail_on_severity_exits_one_when_met() {
    // MSC04-C is Medium severity
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "--fail-on-severity",
        "Medium",
    ]);
    assert_eq!(code, 1);
}

#[test]
fn fail_on_severity_exits_zero_when_below() {
    // MSC04-C is Medium — threshold High means no match
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "--fail-on-severity",
        "High",
    ]);
    assert_eq!(code, 0);
}

// ─── Filtering ───────────────────────────────────────────────────────────────

#[test]
fn min_severity_filters_below_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    // MSC04-C is Medium — High threshold should filter it out
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "--min-severity",
        "High",
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(
        violations.is_empty(),
        "Medium violation should be filtered by High threshold"
    );
}

#[test]
fn min_severity_passes_at_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "--min-severity",
        "Medium",
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert_eq!(violations.len(), 1);
}

#[test]
fn rules_filter_includes_matching_rule() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "--rules",
        "MSC04-C",
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert_eq!(violations.len(), 1);
}

#[test]
fn rules_filter_excludes_non_matching() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "--rules",
        "DCL31-C",
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(
        violations.is_empty(),
        "MSC04-C should be excluded by DCL31-C filter"
    );
}

// ─── Prescan caching ─────────────────────────────────────────────────────────

#[test]
fn prescan_save_load_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("prescan.bin");
    let out1 = dir.path().join("save.json");
    let out2 = dir.path().join("load.json");

    let project_main = fixtures().join("project/main.c");
    let helpers_dir = fixtures().join("project/helpers");

    // Save prescan — with -d, DCL31-C violation is suppressed
    let (code, _, _) = run_aurora_lint(&[
        project_main.to_str().unwrap(),
        "-m",
        manifest_dcl31().to_str().unwrap(),
        "-d",
        helpers_dir.to_str().unwrap(),
        "--save-prescan",
        cache.to_str().unwrap(),
        "-e",
        out1.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert!(cache.exists(), "prescan cache file should be created");

    // Load prescan — same result without needing -d
    let (code, _, _) = run_aurora_lint(&[
        project_main.to_str().unwrap(),
        "-m",
        manifest_dcl31().to_str().unwrap(),
        "--load-prescan",
        cache.to_str().unwrap(),
        "-e",
        out2.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let save_violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out1).unwrap()).unwrap();
    let load_violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out2).unwrap()).unwrap();

    assert!(
        save_violations.is_empty(),
        "With -d, helper_compute should be known"
    );
    assert_eq!(
        save_violations.len(),
        load_violations.len(),
        "Loaded prescan should produce same results as live prescan"
    );
}

/// A cache records the include-name rule it was built under, since which
/// headers it read depends on it, and is refused under the other rule.
#[test]
fn prescan_cache_is_refused_under_other_include_names() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("prescan.bin");
    let main_c = fixtures().join("project/main.c");
    let scan = |names: &str, cache_flag: &str| {
        run_aurora_lint(&[
            main_c.to_str().unwrap(),
            "-m",
            manifest_dcl31().to_str().unwrap(),
            "--include-names",
            names,
            cache_flag,
            cache.to_str().unwrap(),
        ])
    };
    let (code, _, stderr) = scan("case-insensitive", "--save-prescan");
    assert_eq!(code, 0, "{stderr}");
    let (code, _, stderr) = scan("case-insensitive", "--load-prescan");
    assert_eq!(code, 0, "{stderr}");
    let (code, _, stderr) = scan("exact", "--load-prescan");
    assert_ne!(code, 0);
    assert!(
        stderr.contains("include_names = case-insensitive")
            && stderr.contains("include_names = exact"),
        "{stderr}"
    );
}

/// Regression (Phase 2c-i): a function-like macro invocation
/// (`xfree(p)`, defined in a header reached via -d) must not be flagged by
/// DCL31-C as an undeclared function. This is the curl `curlx_free`/`curlx_calloc`
/// false-positive class — the prescan pre-pass collects the macro definitions
/// into ProjectContext.function_macros, which DCL31-C now consumes.
#[test]
fn function_like_macro_not_flagged_as_undeclared() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");

    let main_c = fixtures().join("macro_wrappers/main.c");
    let include_dir = fixtures().join("macro_wrappers/include");

    let (code, _, _) = run_aurora_lint(&[
        main_c.to_str().unwrap(),
        "-m",
        manifest_dcl31().to_str().unwrap(),
        "-d",
        include_dir.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert!(
        violations.is_empty(),
        "function-like macros xfree/xcalloc must not be flagged as undeclared \
         functions; got: {violations:?}"
    );
}

fn manifest_exp33() -> PathBuf {
    fixtures().join("manifest_exp33.toml")
}

/// EXP33-C findings in `use.c` when the whole fixture directory is
/// prescanned with `-d`, optionally declaring the scan a closed program: the
/// branch on the flag is pruned only when the flag is a proven constant.
fn exp33_findings_in_use_c(fixture: &str, closed_program: bool) -> usize {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join(fixture);
    let use_c = fixture_dir.join("use.c");
    let manifest = manifest_exp33();
    let mut args = vec![
        use_c.to_str().unwrap(),
        "-m",
        manifest.to_str().unwrap(),
        "-d",
        fixture_dir.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ];
    if closed_program {
        args.extend(["--set", "closed_program=true"]);
    }
    let (code, _, _) = run_aurora_lint(&args);
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    violations
        .iter()
        .filter(|v| v["rule_id"] == "EXP33-C")
        .count()
}

/// Juliet's shape: in a declared closed program, a non-static flag no
/// scanned file writes folds, and the branch it guards is dead.
#[test]
fn exp33_never_written_global_prunes_its_branch_in_a_closed_program() {
    assert_eq!(
        exp33_findings_in_use_c("exp33_global_never_written", true),
        0
    );
}

/// Undeclared, the scan may be a library another translation unit writes
/// the flag from (ADR-0011), so it is not folded.
#[test]
fn exp33_never_written_global_is_not_folded_unless_the_program_is_closed() {
    assert_eq!(
        exp33_findings_in_use_c("exp33_global_never_written", false),
        1
    );
}

/// A non-static function that only returns a literal folds in a closed
/// program; otherwise another translation unit may interpose it.
#[test]
fn exp33_constant_returning_function_folds_only_in_a_closed_program() {
    assert_eq!(
        exp33_findings_in_use_c("exp33_constant_returning_function", true),
        0
    );
    assert_eq!(
        exp33_findings_in_use_c("exp33_constant_returning_function", false),
        1
    );
}

/// Another file writes the flag through its extern declaration, so it is
/// not a constant and the branch runs, closed program or not.
#[test]
fn exp33_global_written_in_another_file_does_not_prune() {
    assert_eq!(
        exp33_findings_in_use_c("exp33_global_written_elsewhere", true),
        1
    );
    assert_eq!(
        exp33_findings_in_use_c("exp33_global_written_elsewhere", false),
        1
    );
}

/// Two #if arms define the flag with different values: no one value holds,
/// so neither is folded (the last definition merged used to win).
#[test]
fn exp33_global_defined_differently_per_configuration_does_not_prune() {
    assert_eq!(
        exp33_findings_in_use_c("exp33_global_conflicting_arms", true),
        1
    );
}

/// The checked file's own non-static literal-returning function folds only
/// in a closed program, whether or not the file is in the prescan set.
#[test]
fn exp33_checked_files_own_constant_function_folds_only_in_a_closed_program() {
    assert_eq!(
        exp33_findings_in_use_c("exp33_constant_function_in_checked_file", true),
        0
    );
    assert_eq!(
        exp33_findings_in_use_c("exp33_constant_function_in_checked_file", false),
        1
    );
    // Against a prescan cache built from other files, which never saw this
    // function: the storage class alone must decide.
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("foreign.prescan");
    let out = dir.path().join("out.json");
    let foreign = fixtures().join("exp33_global_never_written");
    let use_c = fixtures().join("exp33_constant_function_in_checked_file/use.c");
    let manifest = manifest_exp33();
    let (code, _, _) = run_aurora_lint(&[
        foreign.join("use.c").to_str().unwrap(),
        "-m",
        manifest.to_str().unwrap(),
        "-d",
        foreign.to_str().unwrap(),
        "--save-prescan",
        cache.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let (code, _, _) = run_aurora_lint(&[
        use_c.to_str().unwrap(),
        "-m",
        manifest.to_str().unwrap(),
        "--load-prescan",
        cache.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert_eq!(
        violations
            .iter()
            .filter(|v| v["rule_id"] == "EXP33-C")
            .count(),
        1
    );
}

/// A header's never-written static is each includer's own copy: an includer
/// that writes it must not have its branch folded.
#[test]
fn exp33_header_static_written_by_an_includer_does_not_prune() {
    assert_eq!(
        exp33_findings_in_use_c("exp33_header_static_written_by_includer", false),
        1
    );
}

/// A tentative `int globalOn;` in one #if arm is 0 in that build, so the
/// other arm's `= 1` is no constant for every configuration (ADR-0010).
#[test]
fn exp33_global_tentative_in_one_arm_does_not_fold() {
    assert_eq!(
        exp33_findings_in_use_c("exp33_global_tentative_in_one_arm", true),
        1
    );
}

/// An initializer the scan cannot evaluate in one #if arm leaves the global
/// no one value, whatever another arm initializes it to.
#[test]
fn exp33_global_computed_in_one_arm_does_not_fold() {
    assert_eq!(
        exp33_findings_in_use_c("exp33_global_computed_in_one_arm", true),
        1
    );
}

/// A volatile global is never a constant, closed program or not.
#[test]
fn exp33_volatile_global_does_not_prune() {
    assert_eq!(exp33_findings_in_use_c("exp33_volatile_global", true), 1);
}

/// A pointer global initialized to 0 is not the integer constant 0.
#[test]
fn exp33_pointer_global_is_not_an_integer_constant() {
    assert_eq!(exp33_findings_in_use_c("exp33_pointer_global", true), 1);
}

/// A never-written static in one file is not the same-named, written static
/// in another (ADR-0006): it must not fold that file's branch.
#[test]
fn exp33_static_in_one_file_does_not_fold_another_files_static() {
    assert_eq!(
        exp33_findings_in_use_c("exp33_static_scoped_per_file", true),
        1
    );
}

/// A variable written by a function-like *output* macro (the macro body assigns
/// it, e.g. curl's `CF_DATA_SAVE(save, …)`) must not be flagged by EXP33-C as
/// "used uninitialized" — neither at the macro's output-argument position nor at
/// a later read. The prescan collects the macro definition into
/// ProjectContext.function_macros; `macro_output_param_indices` identifies the
/// assigned parameter; EXP33-C's read-checker and the init-state transfer both
/// consume it. This is the curl CF_DATA_SAVE FP class (Phase 2c-ii).
#[test]
fn macro_output_arg_not_flagged_uninitialized() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");

    let main_c = fixtures().join("macro_out_param/main.c");
    let include_dir = fixtures().join("macro_out_param/include");

    let (code, _, _) = run_aurora_lint(&[
        main_c.to_str().unwrap(),
        "-m",
        manifest_exp33().to_str().unwrap(),
        "-d",
        include_dir.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert!(
        violations.is_empty(),
        "macro-output variable `save` (written by DATA_SAVE) must not be flagged \
         as used-uninitialized; got: {violations:?}"
    );
}

/// An argument that one build's macro definition drops is not read at the
/// invocation: `GET(v)` is `((v) = f())` in one build and `0` in the other,
/// so `v` stays uninitialized in the second and EXP33-C reports the later
/// `use(v)`, not `GET(v)`, which reads nothing in either build. The
/// generated fixture test only sees that EXP33-C fires, so the line is
/// asserted here from the fixture's UNINIT-USE tag.
#[test]
fn a_dropped_macro_argument_is_reported_at_its_next_use() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "src/rules/cert_c/EXP/EXP33-C/tests/fail/\
         macro_that_drops_its_argument_in_one_arm_leaves_it_unwritten.c",
    );

    let (code, _, _) = run_aurora_lint(&[
        fixture.to_str().unwrap(),
        "-m",
        manifest_exp33().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let source = std::fs::read_to_string(&fixture).unwrap();
    let tagged = source
        .lines()
        .position(|text| text.contains("UNINIT-USE"))
        .map(|idx| idx as u64 + 1)
        .expect("fixture lost its UNINIT-USE tag");
    let lines: Vec<u64> = violations
        .iter()
        .filter_map(|v| v["line"].as_u64())
        .collect();
    assert_eq!(lines, vec![tagged], "got: {violations:?}");
}

// ─── Suppression ─────────────────────────────────────────────────────────────

#[test]
fn inline_suppression_hides_violation() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, stdout, _) = run_aurora_lint(&[
        fixtures().join("suppressed_inline.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("1 suppressed"),
        "Should report 1 suppressed violation"
    );

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(
        violations.is_empty(),
        "Suppressed violation should not appear in JSON export"
    );
}

/// The pre-rename `SQC-SUPPRESS` spelling stays accepted (see
/// `inline_suppression_hides_violation`, whose fixture still uses it), but new
/// suppressions are written as `AURORA-SUPPRESS`. Both must resolve to the same
/// hash, since the hash covers only the code portion of the line.
#[test]
fn inline_suppression_accepts_canonical_directive() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, stdout, _) = run_aurora_lint(&[
        fixtures()
            .join("suppressed_inline_aurora.c")
            .to_str()
            .unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("1 suppressed"),
        "AURORA-SUPPRESS should suppress just as SQC-SUPPRESS does"
    );

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(violations.is_empty());
}

#[test]
fn toml_suppression_hides_violation() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, stdout, _) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "--suppress-file",
        fixtures().join("suppress.toml").to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("1 suppressed"),
        "Should report 1 suppressed violation"
    );

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(
        violations.is_empty(),
        "TOML-suppressed violation should not appear in JSON export"
    );
}

/// `suppress.toml`'s `tool` field accepts the new name; the legacy `"sqc"`
/// value is covered by `toml_suppression_hides_violation`'s fixture.
#[test]
fn toml_suppression_accepts_canonical_tool_name() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, stdout, _) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "--suppress-file",
        fixtures().join("suppress_aurora.toml").to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("1 suppressed"));

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(violations.is_empty());
}

/// A suppression file in a shape aurora-lint does not read stops the run
/// with a configuration error (exit 2) naming the table, instead of loading
/// no entries and reporting the findings it was written to suppress.
#[test]
fn suppress_file_with_unknown_table_is_an_error() {
    let (code, stdout, stderr) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "--suppress-file",
        fixtures()
            .join("suppress_older_spelling.toml")
            .to_str()
            .unwrap(),
    ]);
    assert_eq!(code, 2, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("suppress_older_spelling.toml"), "{stderr}");
    assert!(stderr.contains("unknown table `wildcard`"), "{stderr}");
    assert!(!stdout.contains("Total violations"), "{stdout}");
}

#[test]
fn suppress_file_with_unknown_key_is_an_error() {
    let (code, _, stderr) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "--suppress-file",
        fixtures()
            .join("suppress_unknown_key.toml")
            .to_str()
            .unwrap(),
    ]);
    assert_eq!(code, 2, "{stderr}");
    assert!(
        stderr.contains("suppress entry 'violation-msc04' has unknown key `reason`"),
        "{stderr}"
    );
    assert!(stderr.contains("allowed: name, tool,"), "{stderr}");
}

#[test]
fn fail_on_violation_ignores_suppressed() {
    // Suppressed violations should NOT trigger exit code 1
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("suppressed_inline.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "--fail-on-violation",
    ]);
    assert_eq!(
        code, 0,
        "Suppressed violations should not trigger --fail-on-violation"
    );
}

#[test]
fn generate_suppression_outputs_hash() {
    let (code, stdout, _) = run_aurora_lint(&[
        "--generate-suppression",
        &format!(
            "{}:1:MSC04-C",
            fixtures().join("violation.c").to_str().unwrap()
        ),
        "-m",
        manifest_msc04().to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("AURORA-SUPPRESS: MSC04-C"));
    assert!(stdout.contains("tools:suppress aurora-lint:MSC04-C"));
    assert!(stdout.contains("HASH:745a35718a0e2d31"));
    assert!(stdout.contains("[[suppress]]"));
}

// ─── Cross-file analysis (-d) ────────────────────────────────────────────────

#[test]
fn without_d_flag_reports_undeclared_function() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("project/main.c").to_str().unwrap(),
        "-m",
        manifest_dcl31().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert_eq!(
        violations.len(),
        1,
        "Without -d, helper_compute should be flagged"
    );
    assert_eq!(violations[0]["rule_id"], "DCL31-C");
}

#[test]
fn without_d_flag_directory_target_is_its_own_context() {
    // Same helper_compute, but the target is the directory holding both the
    // caller and helpers/helper.c. With no -d the scan set itself is
    // prescanned, so the definition is known without naming the
    // directory a second time with -d.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("project").to_str().unwrap(),
        "-m",
        manifest_dcl31().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(
        violations.is_empty(),
        "A directory target must see its own helpers/helper.c without -d: {content}"
    );
}

#[test]
fn without_d_flag_single_file_sees_its_own_definitions() {
    // A single-file target with no -d: the two callees are defined later in
    // the same file. Before an earlier fix only sibling headers were consulted and
    // the file's own definitions were never prescanned, so both calls were
    // flagged -- and vanished the moment the same file's directory was
    // passed with -d.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures()
            .join("intrafile/forward_call.c")
            .to_str()
            .unwrap(),
        "-m",
        manifest_dcl31().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(
        violations.is_empty(),
        "A single-file target must see its own later definitions without -d: {content}"
    );
}

#[test]
fn with_d_flag_suppresses_cross_file_function() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("project/main.c").to_str().unwrap(),
        "-m",
        manifest_dcl31().to_str().unwrap(),
        "-d",
        fixtures().join("project/helpers").to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(
        violations.is_empty(),
        "With -d helpers/, helper_compute should be known"
    );
}

// ─── Cross-file global null (EXP34-C variant 68) ────────────────────────────

fn manifest_exp34() -> PathBuf {
    fixtures().join("manifest_exp34.toml")
}

#[test]
fn crossfile_global_null_deref_detected_with_d_flag() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("crossfile_null/sink.c").to_str().unwrap(),
        "-m",
        manifest_exp34().to_str().unwrap(),
        "-d",
        fixtures().join("crossfile_null").to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(
        !violations.is_empty(),
        "With -d, shared_buffer=NULL should be detected from source.c and flagged in sink.c"
    );
    assert_eq!(violations[0]["rule_id"], "EXP34-C");
}

#[test]
fn crossfile_global_null_guard_not_flagged() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures()
            .join("crossfile_null/sink_safe.c")
            .to_str()
            .unwrap(),
        "-m",
        manifest_exp34().to_str().unwrap(),
        "-d",
        fixtures().join("crossfile_null").to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let exp34_violations: Vec<&serde_json::Value> = violations
        .iter()
        .filter(|v| v["rule_id"] == "EXP34-C")
        .collect();
    assert!(
        exp34_violations.is_empty(),
        "With null guard, shared_buffer dereference should not be flagged"
    );
}

#[test]
fn crossfile_global_null_not_detected_without_d_flag() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("crossfile_null/sink.c").to_str().unwrap(),
        "-m",
        manifest_exp34().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let exp34_violations: Vec<&serde_json::Value> = violations
        .iter()
        .filter(|v| v["rule_id"] == "EXP34-C")
        .collect();
    assert!(
        exp34_violations.is_empty(),
        "Without -d, cross-file global null state is unknown — no EXP34-C violation expected"
    );
}

// ─── Diff mode ───────────────────────────────────────────────────────────────

#[test]
fn diff_mode_only_analyzes_modified_files() {
    // Set up a temporary git repo with one clean committed file
    // and one modified file with a violation
    let dir = tempfile::tempdir().unwrap();
    let repo_dir = dir.path();

    // Init git repo. Scrub inherited git env vars (see git_in) so these commands
    // operate on the temp repo and not whatever repo a parent `git commit` hook
    // is building.
    git_in(repo_dir, &["init"]);
    git_in(repo_dir, &["config", "user.email", "test@test.com"]);
    git_in(repo_dir, &["config", "user.name", "Test"]);

    // Create and commit a clean file
    let clean = repo_dir.join("clean.c");
    std::fs::write(&clean, "int add(int a, int b) { return a + b; }\n").unwrap();
    git_in(repo_dir, &["add", "clean.c"]);
    git_in(repo_dir, &["commit", "-m", "initial"]);

    // Add an untracked file with a violation
    let violation = repo_dir.join("violation.c");
    std::fs::write(&violation, "void infinite(void) {\n    infinite();\n}\n").unwrap();

    // Copy manifest into the repo
    let manifest = repo_dir.join("manifest.toml");
    std::fs::copy(manifest_msc04(), &manifest).unwrap();

    let out = repo_dir.join("out.json");

    // --diff should only analyze the new/modified file
    // Must run from within the repo so aurora-lint detects the git context correctly.
    // Scrub inherited git env vars so aurora-lint's internal `git diff` targets this
    // temp repo, not a parent hook's repo (see git_in).
    let output = scrub_git_env(&mut Command::new(aurora_lint_bin()))
        .args([
            repo_dir.to_str().unwrap(),
            "-m",
            manifest.to_str().unwrap(),
            "--diff",
            "-e",
            out.to_str().unwrap(),
        ])
        .current_dir(repo_dir)
        .output()
        .expect("failed to execute aurora-lint");

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert_eq!(code, 0);
    assert!(
        stdout.contains("diff-only"),
        "Should indicate diff-only mode"
    );

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    // Should find MSC04-C in the new violation.c file
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0]["rule_id"], "MSC04-C");
    // Should NOT have analyzed clean.c (it's committed and unmodified)
}

/// A repository whose `main` holds a clean file plus one with a violation
/// (`old.c`) and one more (`gone.c`), and whose checked-out `feature` branch
/// commits a new violating file, renames `old.c` to `renamed.c` and deletes
/// `gone.c`. The working tree is clean, as in a CI checkout of a PR.
fn branch_repo(repo_dir: &std::path::Path) {
    const VIOLATION: &str = "void infinite(void) {\n    infinite();\n}\n";
    git_in(repo_dir, &["init", "-b", "main"]);
    git_in(repo_dir, &["config", "user.email", "test@test.com"]);
    git_in(repo_dir, &["config", "user.name", "Test"]);
    std::fs::write(
        repo_dir.join("clean.c"),
        "int add(int a, int b) { return a + b; }\n",
    )
    .unwrap();
    std::fs::write(
        repo_dir.join("old.c"),
        VIOLATION.replace("infinite", "loop1"),
    )
    .unwrap();
    std::fs::write(
        repo_dir.join("gone.c"),
        VIOLATION.replace("infinite", "loop2"),
    )
    .unwrap();
    std::fs::copy(manifest_msc04(), repo_dir.join("manifest.toml")).unwrap();
    git_in(repo_dir, &["add", "."]);
    git_in(repo_dir, &["commit", "-m", "initial"]);
    git_in(repo_dir, &["checkout", "-b", "feature"]);
    std::fs::create_dir(repo_dir.join("src")).unwrap();
    std::fs::write(repo_dir.join("src/added.c"), VIOLATION).unwrap();
    git_in(repo_dir, &["add", "src/added.c"]);
    git_in(repo_dir, &["mv", "old.c", "renamed.c"]);
    git_in(repo_dir, &["rm", "-q", "gone.c"]);
    git_in(repo_dir, &["commit", "-m", "feature"]);
}

/// Run aurora-lint on `path` from `cwd` with a JSON export, git environment
/// scrubbed. Returns (exit code, stdout, stderr, the files with findings).
fn run_diff_scan(
    cwd: &std::path::Path,
    path: &std::path::Path,
    extra: &[&str],
) -> (i32, String, String, Vec<String>) {
    let out_dir = tempfile::tempdir().unwrap();
    let out = out_dir.path().join("out.json");
    let manifest = fixtures().join("manifest_msc04.toml");
    let output = scrub_git_env(&mut Command::new(aurora_lint_bin()))
        .arg(path)
        .args([
            "-m",
            manifest.to_str().unwrap(),
            "-e",
            out.to_str().unwrap(),
        ])
        .args(extra)
        .current_dir(cwd)
        .output()
        .expect("failed to execute aurora-lint");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let mut files: Vec<String> = std::fs::read_to_string(&out)
        .ok()
        .map(|c| {
            let v: Vec<serde_json::Value> = serde_json::from_str(&c).unwrap();
            v.iter()
                .map(|f| {
                    let file = f["file"].as_str().unwrap().replace('\\', "/");
                    file.rsplit_once(path.file_name().unwrap().to_str().unwrap())
                        .map_or(file.clone(), |(_, rest)| {
                            rest.trim_start_matches('/').to_string()
                        })
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    (code, stdout, stderr, files)
}

#[test]
fn diff_base_on_a_clean_tree_scans_the_files_the_branch_changed() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    branch_repo(&repo);
    let elsewhere = tempfile::tempdir().unwrap();

    // --diff alone sees no uncommitted change, so nothing is scanned: the
    // reason a pull-request job needs a base ref.
    let (code, _, stderr, files) = run_diff_scan(elsewhere.path(), &repo, &["--diff"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(files.is_empty(), "{files:?}");

    // From a directory outside the repository too: the added file and the
    // renamed one under its new name; the deleted file is no error.
    let (code, stdout, stderr, files) =
        run_diff_scan(elsewhere.path(), &repo, &["--diff-base", "main"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("merge base with main"), "{stdout}");
    assert_eq!(files, ["renamed.c", "src/added.c"]);
}

#[test]
fn diff_base_also_scans_uncommitted_and_untracked_files() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    branch_repo(&repo);
    // An untracked file in an untracked directory, and an uncommitted edit.
    std::fs::create_dir(repo.join("new_dir")).unwrap();
    std::fs::write(
        repo.join("new_dir/untracked.c"),
        "void spin(void) {\n    spin();\n}\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("clean.c"),
        "int add(int a, int b) { return a + b; }\nvoid again(void) {\n    again();\n}\n",
    )
    .unwrap();

    let (code, _, stderr, files) = run_diff_scan(&repo, &repo, &["--diff"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(files, ["clean.c", "new_dir/untracked.c"]);

    let (code, _, stderr, files) = run_diff_scan(&repo, &repo, &["--diff-base", "main"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(
        files,
        ["clean.c", "new_dir/untracked.c", "renamed.c", "src/added.c"]
    );
}

#[test]
fn diff_refuses_a_path_that_is_not_the_repository_root() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    branch_repo(&repo);

    for flags in [&["--diff"][..], &["--diff-base", "main"][..]] {
        let (code, _, stderr, files) = run_diff_scan(&repo, &repo.join("src"), flags);
        assert_eq!(code, 2, "{flags:?} stderr: {stderr}");
        assert!(stderr.contains("root of the git repository"), "{stderr}");
        assert!(files.is_empty());
    }

    // Outside any repository there is nothing to diff against either.
    let plain = tempfile::tempdir().unwrap();
    std::fs::write(plain.path().join("a.c"), "int x;\n").unwrap();
    let (code, _, stderr, _) = run_diff_scan(plain.path(), plain.path(), &["--diff"]);
    assert_eq!(code, 2, "stderr: {stderr}");
    assert!(stderr.contains("not inside one"), "{stderr}");
}

#[test]
fn diff_base_names_a_missing_ref_and_a_shallow_history() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    branch_repo(&repo);

    let (code, _, stderr, _) = run_diff_scan(&repo, &repo, &["--diff-base", "origin/main"]);
    assert_eq!(code, 2, "stderr: {stderr}");
    assert!(
        stderr.contains("'origin/main' does not name a commit") && stderr.contains("git fetch"),
        "{stderr}"
    );

    // A depth-1 clone holds both branch tips but not the commit joining them.
    git_in(&repo, &["checkout", "-q", "main"]);
    std::fs::write(repo.join("later.c"), "int later;\n").unwrap();
    git_in(&repo, &["add", "later.c"]);
    git_in(&repo, &["commit", "-m", "main moves on"]);
    git_in(&repo, &["checkout", "-q", "feature"]);
    let url = format!("file://{}", repo.display());
    git_in(
        dir.path(),
        &[
            "clone",
            "-q",
            "--depth",
            "1",
            "--no-single-branch",
            &url,
            "shallow",
        ],
    );
    let shallow = dir.path().join("shallow");
    let (code, _, stderr, _) = run_diff_scan(&shallow, &shallow, &["--diff-base", "origin/main"]);
    assert_eq!(code, 2, "stderr: {stderr}");
    assert!(
        stderr.contains("shallow clone") && stderr.contains("fetch-depth: 0"),
        "{stderr}"
    );
}

// ─── SARIF suppression output ────────────────────────────────────────────────

#[test]
fn sarif_includes_suppressed_violations() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.sarif");
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("suppressed_inline.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&content).unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();

    // SARIF should include suppressed violations with suppression metadata
    let suppressed: Vec<_> = results
        .iter()
        .filter(|r| r.get("suppressions").is_some())
        .collect();
    assert!(
        !suppressed.is_empty(),
        "SARIF should include suppressed violations with suppressions array"
    );
}

// ─── Cross-file callsite null propagation (EXP34-C) ─────────────────────────

#[test]
fn crossfile_callsite_null_detected_with_d_flag() {
    // caller_bad.c calls process_data(NULL); callee.c dereferences param.
    // With -d, prescan should propagate NULL arg → EXP34-C flags dereference.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("crossfile_callsite_null");
    let (code, _, _) = run_aurora_lint(&[
        fixture_dir.join("callee.c").to_str().unwrap(),
        "-m",
        manifest_exp34().to_str().unwrap(),
        "-d",
        fixture_dir.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let exp34: Vec<_> = violations
        .iter()
        .filter(|v| v["rule_id"] == "EXP34-C")
        .collect();
    assert!(
        !exp34.is_empty(),
        "With -d, callsite NULL propagation should cause EXP34-C to flag dereference in callee.c"
    );
}

#[test]
fn crossfile_callsite_null_not_detected_without_d_flag() {
    // Without -d, no cross-file context — callee.c alone has no reason to flag.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("crossfile_callsite_null");
    let (code, _, _) = run_aurora_lint(&[
        fixture_dir.join("callee.c").to_str().unwrap(),
        "-m",
        manifest_exp34().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let exp34: Vec<_> = violations
        .iter()
        .filter(|v| v["rule_id"] == "EXP34-C")
        .collect();
    assert!(
        exp34.is_empty(),
        "Without -d, callee.c has no NULL context — no EXP34-C expected"
    );
}

#[test]
fn crossfile_callsite_safe_not_flagged() {
    // caller_safe.c passes &value (NotNull) to process_data().
    // Analyzing callee.c with -d should NOT flag when all callers pass non-NULL.
    // We analyze with only callee.c + caller_safe.c (exclude caller_bad.c).
    let dir = tempfile::tempdir().unwrap();
    let safe_dir = dir.path().join("safe_only");
    std::fs::create_dir_all(&safe_dir).unwrap();
    let fixture_dir = fixtures().join("crossfile_callsite_null");

    // Copy only callee.c and caller_safe.c
    std::fs::copy(fixture_dir.join("callee.c"), safe_dir.join("callee.c")).unwrap();
    std::fs::copy(
        fixture_dir.join("caller_safe.c"),
        safe_dir.join("caller_safe.c"),
    )
    .unwrap();

    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        safe_dir.join("callee.c").to_str().unwrap(),
        "-m",
        manifest_exp34().to_str().unwrap(),
        "-d",
        safe_dir.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let exp34: Vec<_> = violations
        .iter()
        .filter(|v| v["rule_id"] == "EXP34-C")
        .collect();
    assert!(
        exp34.is_empty(),
        "With only safe callers (non-NULL args), callee.c should not be flagged"
    );
}

// ─── Cross-file can_return_null (EXP34-C) ───────────────────────────────────

#[test]
fn crossfile_nullable_return_detected_with_d_flag() {
    // nullable_provider.c wraps malloc (can_return_null = true).
    // nullable_user_bad.c calls it and dereferences without NULL check.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("crossfile_callsite_null");
    let (code, _, _) = run_aurora_lint(&[
        fixture_dir.join("nullable_user_bad.c").to_str().unwrap(),
        "-m",
        manifest_exp34().to_str().unwrap(),
        "-d",
        fixture_dir.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let exp34: Vec<_> = violations
        .iter()
        .filter(|v| v["rule_id"] == "EXP34-C")
        .collect();
    assert!(
        !exp34.is_empty(),
        "With -d, get_buffer() can_return_null → dereference without check should flag EXP34-C"
    );
}

#[test]
fn crossfile_nullable_return_safe_not_flagged() {
    // nullable_user_safe.c checks for NULL before dereference — no violation.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("crossfile_callsite_null");
    let (code, _, _) = run_aurora_lint(&[
        fixture_dir.join("nullable_user_safe.c").to_str().unwrap(),
        "-m",
        manifest_exp34().to_str().unwrap(),
        "-d",
        fixture_dir.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let exp34: Vec<_> = violations
        .iter()
        .filter(|v| v["rule_id"] == "EXP34-C")
        .collect();
    assert!(
        exp34.is_empty(),
        "NULL check after get_buffer() should suppress EXP34-C"
    );
}

// ─── Safe-free macro (MEM30-C, Phase 2c-iii) ────────────────────────────────

fn manifest_mem30() -> PathBuf {
    fixtures().join("manifest_mem30.toml")
}

/// A pointer freed-and-nulled by a "safe free" function-like macro (the body
/// does `free(p); (p) = NULL;`, e.g. curl's `Curl_safefree`) must not be flagged
/// by MEM30-C as a double-free (a second safe-free is `free(NULL)`) or
/// use-after-free (the pointer is NULL, not dangling). MEM30-C already treats
/// the macro as a free via its name; the prescan-collected function_macros +
/// `macro_nulls_param_indices` reveal the hidden `= NULL` so the freed state is
/// cleared. Phase 2c-iii.
#[test]
fn safe_free_macro_not_flagged_double_free() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");

    let main_c = fixtures().join("safe_free_macro/main.c");
    let include_dir = fixtures().join("safe_free_macro/include");

    let (code, _, _) = run_aurora_lint(&[
        main_c.to_str().unwrap(),
        "-m",
        manifest_mem30().to_str().unwrap(),
        "-d",
        include_dir.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert!(
        violations.is_empty(),
        "safe-free macro (frees + nulls) must not yield MEM30-C double-free / \
         use-after-free; got: {violations:?}"
    );
}

// ─── DCL18-C message value ──────────────────────────────────────────────────

/// DCL18-C states an octal constant's decimal value with its integer suffix
/// dropped (`017L` is 15, not the 0 a failed parse used to print), and states
/// none for digits that are not octal. Asserted per line from the fixture's
/// `VALUE n` / `VALUE none` tags; the generated fixture test only sees that
/// the rule fires.
#[test]
fn dcl18_message_states_the_octal_value_without_its_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/rules/cert_c/DCL/DCL18-C/tests/fail/suffixed_octal_reports_its_value.c");

    let (code, _, _) = run_aurora_lint(&[
        fixture.to_str().unwrap(),
        "-m",
        fixtures().join("manifest_dcl18.toml").to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let source = std::fs::read_to_string(&fixture).unwrap();
    let mut tagged = 0;
    for (idx, text) in source.lines().enumerate() {
        let Some(tag) = text.split("/* VALUE ").nth(1) else {
            continue;
        };
        let want = tag.trim_end_matches(" */").trim();
        tagged += 1;
        let line = idx as u64 + 1;
        let msg = violations
            .iter()
            .find(|v| v["line"].as_u64() == Some(line))
            .and_then(|v| v["message"].as_str())
            .unwrap_or_else(|| panic!("line {line}: no DCL18-C finding"));
        if want == "none" {
            assert!(
                msg.contains("not a valid octal constant") && !msg.contains("evaluates to"),
                "line {line}: {msg}"
            );
        } else {
            assert!(
                msg.contains(&format!("evaluates to {want} in decimal")),
                "line {line}: {msg}"
            );
        }
    }
    assert_eq!(tagged, 6, "fixture tags changed; update this count");
}

// ─── Cross-file frees_params (MEM31-C) ──────────────────────────────────────

fn manifest_mem31() -> PathBuf {
    fixtures().join("manifest_mem31.toml")
}

/// The loop-array check reports an array whose elements a loop allocates
/// only when this function is the one that should release them. Returned to
/// the caller, kept in a file-scope table, or released by an unwind loop
/// through a project deallocator: none is a loop-array finding. Every
/// real-world loop-array finding relocated to these shapes was one of them.
#[test]
fn loop_array_elements_owned_elsewhere_are_not_reported() {
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cli/loop_array_ownership");
    for name in [
        "returned_to_caller.c",
        "global_table.c",
        "released_by_unwind_loop.c",
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out.json");
        let (code, _, _) = run_aurora_lint(&[
            dir.join(name).to_str().unwrap(),
            "-m",
            manifest_mem31().to_str().unwrap(),
            "-e",
            out.to_str().unwrap(),
        ]);
        assert_eq!(code, 0);
        let violations: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        let loop_findings: Vec<_> = violations
            .iter()
            .filter(|v| {
                v["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("elements allocated in loop"))
            })
            .collect();
        assert!(loop_findings.is_empty(), "{name}: {loop_findings:?}");
    }
}

/// An array whose elements are allocated in a loop is reported at the
/// `array[i] = malloc(...)` that allocates them, not at line 1.
///
/// Both loop-array messages carried a hardcoded `line: 1, column: 1`, so every
/// such finding in one file shared the key (file, 1, MEM31-C) and named a
/// construct that is not on the line. The generated fixture test only sees
/// whether MEM31-C fires, so the line is asserted here from the fixture's own
/// LOOP-ALLOC-SITE tags.
#[test]
fn loop_allocated_array_is_reported_at_its_allocation_site() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "src/rules/cert_c/MEM/MEM31-C/tests/fail/\
         loop_allocated_array_reports_the_allocation_site.c",
    );

    let (code, _, _) = run_aurora_lint(&[
        fixture.to_str().unwrap(),
        "-m",
        manifest_mem31().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let loop_findings: Vec<_> = violations
        .iter()
        .filter(|v| {
            v["message"]
                .as_str()
                .is_some_and(|m| m.contains("elements allocated in loop"))
        })
        .collect();

    let source = std::fs::read_to_string(&fixture).unwrap();
    let tagged: Vec<u64> = source
        .lines()
        .enumerate()
        .filter(|(_, text)| text.contains("LOOP-ALLOC-SITE"))
        .map(|(idx, _)| idx as u64 + 1)
        .collect();
    assert_eq!(tagged.len(), 2, "fixture tags changed; update this count");

    assert_eq!(
        loop_findings.len(),
        tagged.len(),
        "expected one loop-array finding per tagged allocation, got {:?}",
        loop_findings
            .iter()
            .map(|v| (v["line"].clone(), v["message"].clone()))
            .collect::<Vec<_>>()
    );
    for line in &tagged {
        assert_eq!(
            loop_findings
                .iter()
                .filter(|v| v["line"].as_u64() == Some(*line))
                .count(),
            1,
            "line {line}: expected exactly one loop-array finding here"
        );
    }
    assert!(
        !violations
            .iter()
            .any(|v| v["line"].as_u64() == Some(1) && v["rule_id"] == "MEM31-C"),
        "a MEM31-C finding is still reported at line 1"
    );
}

#[test]
fn crossfile_frees_param_suppresses_leak() {
    // caller_good.c allocates and passes to cleanup_buffer() (defined in cleanup.c).
    // With -d, prescan knows cleanup_buffer frees param 0 → no MEM31-C leak.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("crossfile_frees");
    let (code, _, _) = run_aurora_lint(&[
        fixture_dir.join("caller_good.c").to_str().unwrap(),
        "-m",
        manifest_mem31().to_str().unwrap(),
        "-d",
        fixture_dir.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let mem31: Vec<_> = violations
        .iter()
        .filter(|v| v["rule_id"] == "MEM31-C")
        .collect();
    assert!(
        mem31.is_empty(),
        "With -d, cleanup_buffer() frees param 0 → no MEM31-C leak in caller_good.c"
    );
}

#[test]
fn crossfile_frees_param_not_suppressed_without_d_flag() {
    // Without -d, aurora-lint can't know that cleanup_buffer frees param → MEM31-C flags leak.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("crossfile_frees");
    let (code, _, _) = run_aurora_lint(&[
        fixture_dir.join("caller_good.c").to_str().unwrap(),
        "-m",
        manifest_mem31().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let mem31: Vec<_> = violations
        .iter()
        .filter(|v| v["rule_id"] == "MEM31-C")
        .collect();
    assert!(
        !mem31.is_empty(),
        "Without -d, cleanup_buffer() is unknown → MEM31-C should flag leak"
    );
}

#[test]
fn crossfile_actual_leak_detected() {
    // caller_leak.c allocates and never frees — MEM31-C should flag regardless of -d.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("crossfile_frees");
    let (code, _, _) = run_aurora_lint(&[
        fixture_dir.join("caller_leak.c").to_str().unwrap(),
        "-m",
        manifest_mem31().to_str().unwrap(),
        "-d",
        fixture_dir.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let mem31: Vec<_> = violations
        .iter()
        .filter(|v| v["rule_id"] == "MEM31-C")
        .collect();
    assert!(
        !mem31.is_empty(),
        "Actual leak (no free, no cleanup call) should be flagged even with -d"
    );
}

#[test]
fn crossfile_header_constructor_returns_allocation_flags_leak() {
    // make_thing() is a header-defined (static inline) constructor: it calls
    // os_zalloc(), itself header-defined, and returns the result. Both
    // functions are resolved only via #include + -I (not -d), so crediting
    // make_thing() with returns_allocation depends on propagate_returns_
    // allocation rerunning in resolve_includes's re-propagation block
    // . Before that fix this leak was dark.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("crossfile_returns_allocation");
    let include_dir = fixtures().join("crossfile_returns_allocation_include");
    let (code, _, _) = run_aurora_lint(&[
        fixture_dir.join("caller.c").to_str().unwrap(),
        "-m",
        manifest_mem31().to_str().unwrap(),
        "-I",
        include_dir.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let mem31: Vec<_> = violations
        .iter()
        .filter(|v| v["rule_id"] == "MEM31-C")
        .collect();
    assert!(
        !mem31.is_empty(),
        "make_thing()'s header-defined constructor result is dropped — MEM31-C should flag the leak"
    );
}

// ─── DCL31-C's project-wide switch-off for missing generated headers ─────────

/// Scan `dcl31_offswitch/<project>` with `-I <include>` under DCL31-C and
/// return (lines DCL31-C flagged, stderr).
fn dcl31_offswitch_scan(project: &str, include: &str) -> (Vec<u64>, String) {
    let base = fixtures().join("dcl31_offswitch");
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, stderr) = run_aurora_lint(&[
        base.join(project).to_str().unwrap(),
        "-m",
        manifest_dcl31().to_str().unwrap(),
        "-I",
        base.join(include).to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let lines = violations
        .iter()
        .filter(|v| v["rule_id"] == "DCL31-C")
        .map(|v| v["line"].as_u64().unwrap())
        .collect();
    (lines, stderr)
}

#[test]
fn an_include_inside_a_system_header_does_not_switch_dcl31_off() {
    // c-ares' ares.h, reduced: a header off the project, on the search path,
    // includes headers that don't exist on this host while a `sys/` directory
    // sits beside it. Those are the system's missing headers, not the
    // project's, so the undeclared-call check keeps running.
    let (lines, stderr) = dcl31_offswitch_scan("system_includer", "sysinc");
    assert_eq!(lines, vec![6], "never_declared() should be flagged");
    assert!(!stderr.contains("DCL31-C"), "{stderr}");
}

#[test]
fn an_include_in_a_file_proven_dead_arm_does_not_switch_dcl31_off() {
    let (lines, stderr) = dcl31_offswitch_scan("dead_arm", "dead_arm/include");
    assert_eq!(lines, vec![5], "never_declared() should be flagged");
    assert!(!stderr.contains("DCL31-C"), "{stderr}");
}

#[test]
fn a_project_header_off_the_search_path_does_not_switch_dcl31_off() {
    // hostap, reduced: wpa/main.c includes "utils/common.h", which the real
    // build finds through -I src. wpa/utils/ exists too, so the include looks
    // like a missing project header, but the project has the file: the
    // search path is incomplete, nothing was generated.
    let (lines, stderr) = dcl31_offswitch_scan("header_elsewhere", "header_elsewhere/wpa");
    assert_eq!(lines, vec![5], "never_declared() should be flagged");
    assert!(!stderr.contains("DCL31-C"), "{stderr}");
}

#[test]
fn dcl31_stands_down_only_in_files_that_reach_a_missing_generated_header() {
    // One file includes the generated header (through object/structures.h)
    // and goes quiet; its sibling includes nothing generated and is still
    // checked. The warning names the quiet files, not the whole project.
    let base = fixtures().join("dcl31_offswitch");
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, stderr) = run_aurora_lint(&[
        base.join("generated_partial").to_str().unwrap(),
        "-m",
        manifest_dcl31().to_str().unwrap(),
        "-I",
        base.join("generated_partial/include").to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let flagged: Vec<(String, u64)> = violations
        .iter()
        .filter(|v| v["rule_id"] == "DCL31-C")
        .map(|v| {
            let file = v["file"].as_str().unwrap();
            let name = file.rsplit('/').next().unwrap().to_string();
            (name, v["line"].as_u64().unwrap())
        })
        .collect();
    assert_eq!(flagged, vec![("sibling.c".to_string(), 4)]);
    let warning = stderr
        .lines()
        .find(|l| l.contains("DCL31-C"))
        .unwrap_or_else(|| panic!("no stand-down warning in: {stderr}"));
    // Headers are scanned files too: object/structures.h itself includes the
    // generated header.
    assert!(warning.contains("2 of 3 files"), "{warning}");
    assert!(warning.contains("uses_gen.c"), "{warning}");
    assert!(!warning.contains("sibling.c"), "{warning}");
    assert!(warning.contains("object/structures_gen.h"), "{warning}");
}

#[test]
fn dcl31_follows_includes_beyond_the_search_path_to_a_generated_header() {
    // seL4, reduced: src/apic.c includes <arch/machine.h>, which only the
    // per-architecture -I include/arch/x86 would find. The scan is given -I
    // include, follows the project files whose path ends in arch/machine.h
    // (x86 and arm variants), and through the x86 one reaches the generated
    // arch/object/structures_gen.h, so apic.c stands down. other.c includes
    // nothing and is still checked.
    let base = fixtures().join("dcl31_offswitch");
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, stderr) = run_aurora_lint(&[
        base.join("generated_beyond_search_path").to_str().unwrap(),
        "-m",
        manifest_dcl31().to_str().unwrap(),
        "-I",
        base.join("generated_beyond_search_path/include")
            .to_str()
            .unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let flagged: Vec<(String, u64)> = violations
        .iter()
        .filter(|v| v["rule_id"] == "DCL31-C")
        .map(|v| {
            let file = v["file"].as_str().unwrap();
            let name = file.rsplit('/').next().unwrap().to_string();
            (name, v["line"].as_u64().unwrap())
        })
        .collect();
    assert_eq!(flagged, vec![("other.c".to_string(), 3)]);
    let warning = stderr
        .lines()
        .find(|l| l.contains("DCL31-C"))
        .unwrap_or_else(|| panic!("no stand-down warning in: {stderr}"));
    assert!(warning.contains("apic.c"), "{warning}");
    assert!(
        warning.contains("arch/object/structures_gen.h"),
        "{warning}"
    );
}

#[test]
fn a_missing_generated_project_header_switches_dcl31_off_and_says_so() {
    // seL4's layout: the project has include/object/ but structures_gen.h is
    // emitted at build time, so every declaration in it is invisible and the
    // undeclared-call check stands down -- naming the rule, the project and
    // the header rather than going quiet.
    let (lines, stderr) = dcl31_offswitch_scan("generated", "generated/include");
    assert!(
        lines.is_empty(),
        "pte_new() is declared in the missing header"
    );
    let warning = stderr
        .lines()
        .find(|l| l.contains("DCL31-C"))
        .unwrap_or_else(|| panic!("no switch-off warning in: {stderr}"));
    assert!(warning.contains("dcl31_offswitch/generated"), "{warning}");
    assert!(warning.contains("object/structures_gen.h"), "{warning}");
}

// ─── Cross-file header-declared functions (DCL15-C) ─────────────────────────

fn manifest_dcl15() -> PathBuf {
    fixtures().join("manifest_dcl15.toml")
}

#[test]
fn crossfile_header_declared_suppresses_dcl15c() {
    // impl.c defines compute_value() and print_result() prototyped in public_api.h.
    // With -d, prescan sees the header prototypes → DCL15-C should NOT flag them.
    // internal_helper() has no header prototype → should still be flagged.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("crossfile_header");
    let (code, _, _) = run_aurora_lint(&[
        fixture_dir.join("impl.c").to_str().unwrap(),
        "-m",
        manifest_dcl15().to_str().unwrap(),
        "-d",
        fixture_dir.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let dcl15: Vec<_> = violations
        .iter()
        .filter(|v| v["rule_id"] == "DCL15-C")
        .collect();

    // Should flag internal_helper but NOT compute_value or print_result
    let flagged_names: Vec<String> = dcl15
        .iter()
        .map(|v| v["message"].as_str().unwrap_or("").to_string())
        .collect();
    assert!(
        !flagged_names.iter().any(|m| m.contains("compute_value")),
        "compute_value() has header prototype — DCL15-C should not flag it"
    );
    assert!(
        !flagged_names.iter().any(|m| m.contains("print_result")),
        "print_result() has header prototype — DCL15-C should not flag it"
    );
    assert!(
        flagged_names.iter().any(|m| m.contains("internal_helper")),
        "internal_helper() has no header prototype — DCL15-C should flag it"
    );
}

fn manifest_sig01() -> PathBuf {
    fixtures().join("manifest_sig01.toml")
}

#[test]
fn crossfile_header_declared_signal_handler_is_registered() {
    // main.c passes on_int to signal(); on_int is only declared, in
    // handlers.h, and defined in handlers.c. The handler resolves through
    // the project's header declarations, so SIG01-C sees the registration.
    // Before that, a handler with no declaration in the scanned file
    // registered nothing and the signal() call was dark.
    let fixture_dir = fixtures().join("crossfile_signal_handler");
    for with_d in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out.json");
        let mut args = vec![
            fixture_dir.join("main.c").to_str().unwrap().to_string(),
            "-m".to_string(),
            manifest_sig01().to_str().unwrap().to_string(),
            "-e".to_string(),
            out.to_str().unwrap().to_string(),
        ];
        if with_d {
            args.push("-d".to_string());
            args.push(fixture_dir.to_str().unwrap().to_string());
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let (code, _, _) = run_aurora_lint(&args);
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(&out).unwrap();
        let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
        let sig01: Vec<_> = violations
            .iter()
            .filter(|v| v["rule_id"] == "SIG01-C" && v["line"] == 5)
            .collect();
        assert_eq!(
            sig01.len(),
            1,
            "signal(SIGINT, on_int) with a header-declared handler (with_d={with_d})"
        );
    }
}

fn manifest_sig34() -> PathBuf {
    fixtures().join("manifest_sig34.toml")
}

fn sig34_lines(file: &str) -> Vec<u64> {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("crossfile_sig34");
    let (code, _, _) = run_aurora_lint(&[
        fixture_dir.join(file).to_str().unwrap(),
        "-m",
        manifest_sig34().to_str().unwrap(),
        "-d",
        fixture_dir.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    violations
        .iter()
        .filter(|v| v["rule_id"] == "SIG34-C")
        .map(|v| v["line"].as_u64().unwrap())
        .collect()
}

#[test]
fn crossfile_registered_handler_is_judged_where_it_is_defined() {
    // main.c registers on_int, which handlers.c defines and which calls
    // signal() on another signal. With -d the prescan carries the
    // registration across, so SIG34-C judges handlers.c's definition.
    assert_eq!(sig34_lines("handlers.c"), vec![6]);
}

#[test]
fn crossfile_registration_does_not_reach_a_static_namesake() {
    // other.c's static on_int is its own function, not the one main.c
    // registers, and nothing registers it.
    assert!(sig34_lines("other.c").is_empty());
}

fn manifest_sig30() -> PathBuf {
    fixtures().join("manifest_sig30.toml")
}

#[test]
fn signal_handler_macros_are_judged_by_where_they_are_defined() {
    // sysalias.h sits outside the project, as a C library header would:
    // its remapping of signal() is the implementation's, and its unsafe
    // siglongjmp() is reported by the name the code wrote. projalias.h is
    // the project's own: its remapping of alarm() is judged by the target.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("sig30_macro_origin");
    let project = fixture_dir.join("project");
    let (code, _, _) = run_aurora_lint(&[
        project.join("main.c").to_str().unwrap(),
        "-m",
        manifest_sig30().to_str().unwrap(),
        "-d",
        project.to_str().unwrap(),
        "-I",
        fixture_dir.join("system").to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let found: Vec<(u64, String)> = violations
        .iter()
        .filter(|v| v["rule_id"] == "SIG30-C")
        .map(|v| {
            (
                v["line"].as_u64().unwrap(),
                v["message"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let expected = [
        (17, "calls 'project_alarm()' (through macro 'alarm')"),
        // The macro's parameter is shown as the argument it was given.
        (18, "calls '(g)->log()' (through macro 'CB')"),
        (19, "calls 'siglongjmp()' which"),
    ];
    assert_eq!(found.len(), expected.len(), "{found:?}");
    for ((line, message), (want_line, want)) in found.iter().zip(expected) {
        assert_eq!(*line, want_line, "{found:?}");
        assert!(message.contains(want), "{message}");
    }
}

fn sig30_calls(args: &[&str]) -> Vec<(u64, String)> {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let manifest = manifest_sig30();
    let mut argv: Vec<&str> = args.to_vec();
    argv.extend([
        "-m",
        manifest.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    let (code, _, _) = run_aurora_lint(&argv);
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    violations
        .iter()
        .filter(|v| v["rule_id"] == "SIG30-C")
        .map(|v| {
            (
                v["line"].as_u64().unwrap(),
                v["message"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn a_loaded_prescan_keeps_system_macros_outside_the_project() {
    // A context loaded from a cache carries the system header's definitions
    // too; they must not start counting as the project's when -I resolves
    // the same header again.
    let fixture_dir = fixtures().join("sig30_macro_origin");
    let project = fixture_dir.join("project");
    let main_c = project.join("main.c");
    let system = fixture_dir.join("system");
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_dir.path().join("prescan.bin");
    let direct = sig30_calls(&[
        main_c.to_str().unwrap(),
        "-d",
        project.to_str().unwrap(),
        "-I",
        system.to_str().unwrap(),
        "--save-prescan",
        cache.to_str().unwrap(),
    ]);
    let loaded = sig30_calls(&[
        main_c.to_str().unwrap(),
        "--load-prescan",
        cache.to_str().unwrap(),
        "-I",
        system.to_str().unwrap(),
    ]);
    assert_eq!(loaded, direct);
    assert!(
        loaded
            .iter()
            .all(|(_, m)| !m.contains("__sysv_signal") && !m.contains("__longjmp_chk")),
        "{loaded:?}"
    );
}

#[test]
fn a_single_file_targets_own_tree_is_the_project() {
    // Outside any git repository, a lone file's project is its directory: a
    // header under it, reached through -I, is the project's own remapping.
    let src = fixtures().join("sig30_single_file_root");
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("include")).unwrap();
    for f in ["main.c", "include/remap.h"] {
        std::fs::copy(src.join(f), dir.path().join(f)).unwrap();
    }
    let found = sig30_calls(&[
        dir.path().join("main.c").to_str().unwrap(),
        "-I",
        dir.path().join("include").to_str().unwrap(),
    ]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0]
        .1
        .contains("calls 'project_alarm()' (through macro 'alarm')"));
}

#[test]
fn crossfile_sibling_header_suppresses_public_api_without_d_flag() {
    // aurora-lint auto-scans sibling .h files even without -d, so public API functions
    // declared in public_api.h should NOT be flagged by DCL15-C.
    // Only internal_helper() — which has no header prototype — should be flagged.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("crossfile_header");
    let (code, _, _) = run_aurora_lint(&[
        fixture_dir.join("impl.c").to_str().unwrap(),
        "-m",
        manifest_dcl15().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let dcl15: Vec<_> = violations
        .iter()
        .filter(|v| v["rule_id"] == "DCL15-C")
        .collect();

    // compute_value and print_result are in public_api.h — should not be flagged
    let flagged_names: Vec<_> = dcl15.iter().filter_map(|v| v["message"].as_str()).collect();
    assert!(
        flagged_names
            .iter()
            .all(|m| !m.contains("compute_value") && !m.contains("print_result")),
        "Public API functions declared in sibling header should not be flagged: {:?}",
        flagged_names
    );

    // internal_helper has no header prototype and must still be flagged
    assert!(
        flagged_names.iter().any(|m| m.contains("internal_helper")),
        "internal_helper() has no header prototype — DCL15-C should still flag it (got: {:?})",
        flagged_names
    );
}

// ─── Cross-file caller validation (ARR30-C) ─────────────────────────────────

fn manifest_arr30() -> PathBuf {
    fixtures().join("manifest_arr30.toml")
}

/// The message the unvalidated-parameter-index family reports under.
fn unvalidated_index_findings(out: &std::path::Path) -> Vec<String> {
    let content = std::fs::read_to_string(out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    violations
        .iter()
        .filter(|v| v["rule_id"] == "ARR30-C")
        .filter_map(|v| v["message"].as_str())
        .filter(|m| m.contains("unvalidated function parameter index"))
        .map(str::to_string)
        .collect()
}

#[test]
fn arr30_unvalidated_index_flagged_without_d_flag() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures()
            .join("crossfile_arr30_validated/invoke.c")
            .to_str()
            .unwrap(),
        "-m",
        manifest_arr30().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let findings = unvalidated_index_findings(&out);
    assert!(
        findings.iter().any(|m| m.contains("index")),
        "Without -d there is no call site to summarise, so invoke_inject's \
         index parameter must still be flagged (got: {:?})",
        findings
    );
}

/// `invoke_inject` is exported (declared in a header, not `static`), so its
/// caller set is open: a caller outside the project can pass any index. The
/// range check its one in-tree caller makes is not proof about the parameter
/// (ADR-0011), and the unchecked index is still reported with `-d`.
#[test]
fn arr30_exported_callee_is_not_proven_by_a_crossfile_caller() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures()
            .join("crossfile_arr30_validated/invoke.c")
            .to_str()
            .unwrap(),
        "-m",
        manifest_arr30().to_str().unwrap(),
        "-d",
        fixtures()
            .join("crossfile_arr30_validated")
            .to_str()
            .unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let findings = unvalidated_index_findings(&out);
    assert!(
        findings.iter().any(|m| m.contains("index")),
        "an exported callee's caller-side range check is not proof: \
         invoke_inject's index must still be flagged with -d (got: {:?})",
        findings
    );
}

#[test]
fn arr30_unvalidated_index_survives_one_unguarded_caller() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures()
            .join("crossfile_arr30_unvalidated/invoke.c")
            .to_str()
            .unwrap(),
        "-m",
        manifest_arr30().to_str().unwrap(),
        "-d",
        fixtures()
            .join("crossfile_arr30_unvalidated")
            .to_str()
            .unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let findings = unvalidated_index_findings(&out);
    assert!(
        findings.iter().any(|m| m.contains("index")),
        "raw_inject passes index unchecked, which must disqualify the \
         position for every caller (got: {:?})",
        findings
    );
}

fn manifest_arr36() -> PathBuf {
    fixtures().join("manifest_arr36.toml")
}

/// The cross-file half of ARR36-C's parameter model.
///
/// `span(const char *pos, const char *end)` is checked with no caller in its
/// own file, so the rule's file-local call-site pass has nothing to read and
/// the two parameters stay assumed to share an object. Only the prescan sees
/// `caller.c` handing it two different declared arrays.
#[test]
fn arr36_cross_file_caller_proves_distinct_arrays() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let project = fixtures().join("crossfile_arr36/distinct");

    let (code, _, _) = run_aurora_lint(&[
        project.join("callee.c").to_str().unwrap(),
        "-m",
        manifest_arr36().to_str().unwrap(),
        "-d",
        project.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert_eq!(
        violations.len(),
        1,
        "cross-file caller passes two distinct arrays, so `end - pos` is reportable: {}",
        content
    );
    assert_eq!(violations[0]["rule_id"], "ARR36-C");
}

/// The control for the test above: the same callee, whose only caller passes a
/// cursor and its bound derived from ONE buffer. Nothing proves two objects,
/// so the parameter pair stays assumed to share one.
#[test]
fn arr36_cross_file_caller_passing_one_buffer_proves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let project = fixtures().join("crossfile_arr36/shared");

    let (code, _, _) = run_aurora_lint(&[
        project.join("callee.c").to_str().unwrap(),
        "-m",
        manifest_arr36().to_str().unwrap(),
        "-d",
        project.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(
        violations.is_empty(),
        "one buffer walked by a cursor and its bound is not two arrays: {}",
        content
    );
}

// ─── Cross-file static caller (ENV33-C callers walk) ────────────────────────

fn manifest_env33() -> PathBuf {
    fixtures().join("manifest_env33.toml")
}

/// ENV33-C lines reported in `sink.c` when the whole project is prescanned.
fn env33_sink_lines(project: &str) -> Vec<u64> {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join(project).join("sink.c").to_str().unwrap(),
        "-m",
        manifest_env33().to_str().unwrap(),
        "-d",
        fixtures().join(project).to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    violations
        .iter()
        .filter(|v| v["rule_id"] == "ENV33-C")
        .map(|v| v["line"].as_u64().unwrap())
        .collect()
}

/// A callers walk that climbs from the static sink() to its `static` caller
/// reads that caller's own summary, even though another file defines an
/// unrelated static of the same name. Its caller is clean and the chain is
/// closed (every function on it is `static` or declares no parameters), so
/// sink() is not flagged -- and the other file's `getenv` does not count
/// against it. The chain stays in one file because a cross-file caller has
/// external linkage, and an open caller set proves nothing (ADR-0011).
#[test]
fn callers_walk_reads_the_static_caller_it_reached() {
    assert_eq!(
        env33_sink_lines("crossfile_static_caller_clean"),
        Vec::<u64>::new()
    );
}

/// `rule` lines reported in `project/sink.c`, the project prescanned whole
/// under `manifest`, optionally declared a closed program.
fn closed_program_lines(
    project: &str,
    manifest: &str,
    rule: &str,
    closed_program: bool,
) -> Vec<u64> {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let project = fixtures().join(project);
    let sink = project.join("sink.c");
    let manifest = fixtures().join(manifest);
    let setting = format!("closed_program={closed_program}");
    let (code, _, _) = run_aurora_lint(&[
        sink.to_str().unwrap(),
        "-m",
        manifest.to_str().unwrap(),
        "-d",
        project.to_str().unwrap(),
        "--set",
        &setting,
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let mut lines: Vec<u64> = violations
        .iter()
        .filter(|v| v["rule_id"] == rule)
        .map(|v| v["line"].as_u64().unwrap())
        .collect();
    lines.sort_unstable();
    lines
}

/// Undeclared, a non-static sink's in-tree callers are not all of its
/// callers (ADR-0011), so the literal its one caller passes proves nothing
/// and every format-string sink is reported.
#[test]
fn an_exported_sinks_literal_caller_proves_nothing_unless_the_program_is_closed() {
    assert_eq!(
        closed_program_lines(
            "closed_program_callers",
            "manifest_fio30.toml",
            "FIO30-C",
            false
        ),
        vec![9, 14, 19]
    );
}

/// Declared a closed program, the in-tree callers are all of them, so the
/// literal show_fixed's caller passes proves its format string safe.
/// show_by_pointer's address is stored, so a call through the pointer is
/// one no scan collects; show_arg is reached from main, which the
/// environment calls. Both stay reported.
#[test]
fn a_closed_program_closes_an_exported_sinks_caller_set() {
    assert_eq!(
        closed_program_lines(
            "closed_program_callers",
            "manifest_fio30.toml",
            "FIO30-C",
            true
        ),
        vec![14, 19]
    );
}

/// A caller whose body reads no untrusted input can still pass the defect:
/// here a relative command. ENV33-C's clean-caller walk judges the caller,
/// not the value, so a declared closed program does not make it a proof and
/// the exported sink is reported either way.
#[test]
fn a_closed_program_does_not_turn_a_clean_bodied_caller_into_a_proof() {
    for closed_program in [false, true] {
        assert_eq!(
            closed_program_lines(
                "closed_program_clean_caller",
                "manifest_env33.toml",
                "ENV33-C",
                closed_program
            ),
            vec![9],
            "closed_program = {closed_program}"
        );
    }
}

/// EXP34-C's dereference before a later NULL test: the one call site of
/// `get` passes the address of an object, which proves `q` non-null only
/// over a closed caller set. Undeclared, `get`'s external linkage leaves it
/// open and `q->a` is reported; declared a closed program, the scanned call
/// site is all of them and the later test is redundant.
#[test]
fn exp34_an_exported_functions_nonnull_callers_prove_it_only_in_a_closed_program() {
    let lines = |closed| {
        closed_program_lines(
            "exp34_exported_nonnull_callers",
            "manifest_exp34.toml",
            "EXP34-C",
            closed,
        )
    };
    assert_eq!(lines(false), vec![8]);
    assert_eq!(lines(true), Vec::<u64>::new());
}

/// The caller-set proofs aggregated into a prescan cache depend on the
/// declaration, so a cache built under one is refused under the other.
#[test]
fn a_prescan_cache_is_refused_under_the_other_closed_program_declaration() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("prescan.bin");
    let out = dir.path().join("out.json");
    let project = fixtures().join("closed_program_callers");
    let sink = project.join("sink.c");
    let manifest = fixtures().join("manifest_fio30.toml");
    let run = |extra: &[&str]| {
        let mut args = vec![
            sink.to_str().unwrap(),
            "-m",
            manifest.to_str().unwrap(),
            "-e",
            out.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        run_aurora_lint(&args)
    };
    let (code, _, _) = run(&[
        "-d",
        project.to_str().unwrap(),
        "--save-prescan",
        cache.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let (code, _, _) = run(&["--load-prescan", cache.to_str().unwrap()]);
    assert_eq!(code, 0, "the same declaration reads the cache");
    let (code, stdout, stderr) = run(&[
        "--load-prescan",
        cache.to_str().unwrap(),
        "--set",
        "closed_program=true",
    ]);
    assert_ne!(code, 0, "{stdout}{stderr}");
    assert!(
        format!("{stdout}{stderr}").contains("closed_program"),
        "{stdout}{stderr}"
    );
}

/// The same shape with the taint on the caller the walk reaches and none on
/// the unrelated same-named static: flagged. A walk that read the wrong
/// definition, or pooled both, could not tell these two projects apart.
#[test]
fn callers_walk_does_not_borrow_a_same_named_static() {
    assert_eq!(env33_sink_lines("crossfile_static_caller_tainted"), vec![9]);
}

/// A global's only writer is a `static` in another file whose name a third
/// file also defines static. ENV03-C reads the writer's summary to decide
/// whether the global brings in taint; it must reach that writer from the
/// file that reads the global, and here it writes a fixed command.
#[test]
fn global_writer_resolves_to_the_static_that_wrote_it() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_aurora_lint(&[
        fixtures()
            .join("crossfile_static_writer/sink.c")
            .to_str()
            .unwrap(),
        "-m",
        fixtures().join("manifest_env03.toml").to_str().unwrap(),
        "-d",
        fixtures().join("crossfile_static_writer").to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(
        violations.iter().all(|v| v["rule_id"] != "ENV03-C"),
        "the writer is clean, so the global is not tainted: {violations:?}"
    );
}

/// A struct tag two files define differently resolves to the definition in
/// the file being checked. The project-wide table is keyed by tag and keeps
/// one definition; z_wide_field.c's `unsigned int flags` used to answer for
/// a_narrow_field.c's `unsigned char flags`, hiding its EXP14-C finding.
#[test]
fn struct_tag_defined_twice_resolves_to_the_files_own_definition() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cli/struct_tag_defined_twice");
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules_templates/rules-all.toml");
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out.json");
    let (code, _, stderr) = run_aurora_lint(&[
        dir.to_str().unwrap(),
        "-d",
        dir.to_str().unwrap(),
        "-m",
        manifest.to_str().unwrap(),
        "--rules",
        "EXP14-C",
        "-j",
        "1",
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let narrow: Vec<_> = violations
        .iter()
        .filter(|v| {
            v["rule_id"] == "EXP14-C"
                && v["file"]
                    .as_str()
                    .is_some_and(|f| f.ends_with("a_narrow_field.c"))
        })
        .collect();
    assert_eq!(narrow.len(), 1, "{violations:?}");
}

/// A .c file's static noreturn helper is not another file's same-named
/// static. a_exits.c's die() exits; b_returns.c's returns, so its
/// use-after-free and double free on the `e` path are reported.
#[test]
fn static_noreturn_helper_is_its_own_files() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cli/static_noreturn_defined_twice");
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules_templates/rules-all.toml");
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out.json");
    let (code, _, stderr) = run_aurora_lint(&[
        dir.to_str().unwrap(),
        "-d",
        dir.to_str().unwrap(),
        "-m",
        manifest.to_str().unwrap(),
        "--rules",
        "MEM30-C",
        "-j",
        "1",
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let in_b: Vec<_> = violations
        .iter()
        .filter(|v| {
            v["rule_id"] == "MEM30-C"
                && v["file"]
                    .as_str()
                    .is_some_and(|f| f.ends_with("b_returns.c"))
        })
        .collect();
    assert_eq!(in_b.len(), 2, "{violations:?}");
}

/// A file's own static shadows another file's external function of the same
/// name. a_exits.c's external die() exits; b_returns.c's static die()
/// returns, so its use-after-free and double free on the `e` path are
/// reported.
#[test]
fn own_static_shadows_another_files_external_noreturn() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cli/extern_noreturn_vs_own_static");
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules_templates/rules-all.toml");
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out.json");
    let (code, _, stderr) = run_aurora_lint(&[
        dir.to_str().unwrap(),
        "-d",
        dir.to_str().unwrap(),
        "-m",
        manifest.to_str().unwrap(),
        "--rules",
        "MEM30-C",
        "-j",
        "1",
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let found: Vec<_> = violations
        .iter()
        .filter(|v| {
            v["rule_id"] == "MEM30-C"
                && v["file"]
                    .as_str()
                    .is_some_and(|f| f.ends_with("b_returns.c"))
        })
        .collect();
    assert_eq!(found.len(), 2, "{violations:?}");
}

/// A .c file another .c file #includes is compiled as part of its includer,
/// so helpers.c's static die() ends main.c's `e` path: nothing there is used
/// after free.
#[test]
fn included_c_files_static_noreturn_helper_reaches_its_includer() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cli/included_c_static_noreturn");
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules_templates/rules-all.toml");
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out.json");
    let (code, _, stderr) = run_aurora_lint(&[
        dir.to_str().unwrap(),
        "-d",
        dir.to_str().unwrap(),
        "-m",
        manifest.to_str().unwrap(),
        "--rules",
        "MEM30-C",
        "-j",
        "1",
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let found: Vec<_> = violations
        .iter()
        .filter(|v| {
            v["rule_id"] == "MEM30-C" && v["file"].as_str().is_some_and(|f| f.ends_with("main.c"))
        })
        .collect();
    assert_eq!(found.len(), 0, "{violations:?}");
}

/// A pointer global's null state is joined across the files that define or
/// assign it. z_assigns_buffer.c's non-null assignment used to replace
/// a_defines_null.c's NULL, so m_dereferences.c's dereference went unreported.
#[test]
fn global_pointer_null_state_is_joined_across_files() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cli/global_null_state_joined");
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules_templates/rules-all.toml");
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out.json");
    let (code, _, stderr) = run_aurora_lint(&[
        dir.to_str().unwrap(),
        "-d",
        dir.to_str().unwrap(),
        "-m",
        manifest.to_str().unwrap(),
        "--rules",
        "EXP34-C",
        "-j",
        "1",
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let deref: Vec<_> = violations
        .iter()
        .filter(|v| {
            v["rule_id"] == "EXP34-C"
                && v["file"]
                    .as_str()
                    .is_some_and(|f| f.ends_with("m_dereferences.c"))
        })
        .collect();
    assert_eq!(deref.len(), 1, "{violations:?}");
}

// ---- compile_commands.json from an MSVC build -----------------------------

fn msvc_cdb_fixtures() -> PathBuf {
    fixtures().join("msvc_compile_commands")
}

/// Scan `source` (a file in the MSVC fixture directory) with ARR30-C, with a
/// one-entry compile database whose `command` is `cl_flags` when given, and
/// return the finding messages.
///
/// The source is copied into a project directory of its own and the fixture's
/// `sdk/` header beside it, *outside* the scan root, so only the database's
/// flags can reach the header. The driver is spelled as a Windows path, the
/// way CMake writes a cl database, so the `command` string is split with
/// Windows quoting as well.
fn arr30_messages_with_msvc_cdb(source: &str, cl_flags: Option<&str>) -> Vec<String> {
    arr30_scan_with_msvc_cdb(source, cl_flags, &[]).0
}

/// [`arr30_messages_with_msvc_cdb`] with `extra` arguments appended, also
/// returning stdout and stderr together.
fn arr30_scan_with_msvc_cdb(
    source: &str,
    cl_flags: Option<&str>,
    extra: &[&str],
) -> (Vec<String>, String) {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    let sdk = dir.path().join("sdk");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&sdk).unwrap();
    std::fs::copy(msvc_cdb_fixtures().join(source), project.join(source)).unwrap();
    std::fs::copy(
        msvc_cdb_fixtures().join("sdk/msvc_idx.h"),
        sdk.join("msvc_idx.h"),
    )
    .unwrap();
    let src = project.join(source);
    let out = dir.path().join("out.json");
    let manifest = fixtures().join("manifest_arr30.toml");
    let mut args = vec![
        src.to_str().unwrap().to_string(),
        "-m".into(),
        manifest.to_str().unwrap().to_string(),
        "-e".into(),
        out.to_str().unwrap().to_string(),
    ];
    if let Some(flags) = cl_flags {
        let db = dir.path().join("compile_commands.json");
        let entry = serde_json::json!([{
            "directory": project.to_str().unwrap(),
            "file": src.to_str().unwrap(),
            "command": format!(r"C:\VS\bin\Hostx64\x86\cl.exe /nologo {flags} /W3 /O2 -c {source}"),
        }]);
        std::fs::write(&db, entry.to_string()).unwrap();
        args.push("--compile-commands".into());
        args.push(db.to_str().unwrap().to_string());
    }
    let mut args: Vec<&str> = args.iter().map(String::as_str).collect();
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = run_aurora_lint(&args);
    assert_eq!(code, 0, "{stderr}");
    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let messages = violations
        .iter()
        .map(|v| v["message"].as_str().unwrap().to_string())
        .collect();
    (messages, format!("{stdout}{stderr}"))
}

fn names_index_8(messages: &[String]) -> bool {
    messages.iter().any(|m| m.contains("at index 8"))
}

#[test]
fn msvc_slash_d_define_gates_a_finding() {
    let without = arr30_messages_with_msvc_cdb("define.c", None);
    assert!(!names_index_8(&without), "{without:?}");
    let with = arr30_messages_with_msvc_cdb("define.c", Some("/DIDX=8"));
    assert!(names_index_8(&with), "{with:?}");
    // cl's NAME#VALUE spelling and the separate-token form mean the same.
    let hash = arr30_messages_with_msvc_cdb("define.c", Some("/D IDX#8"));
    assert!(names_index_8(&hash), "{hash:?}");
}

#[test]
fn msvc_slash_i_include_path_gates_a_finding() {
    let without = arr30_messages_with_msvc_cdb("include.c", None);
    assert!(!names_index_8(&without), "{without:?}");
    let with = arr30_messages_with_msvc_cdb("include.c", Some("/I../sdk"));
    assert!(names_index_8(&with), "{with:?}");
}

#[test]
fn msvc_forced_include_gates_a_finding() {
    let without = arr30_messages_with_msvc_cdb("forced.c", Some("/I../sdk"));
    assert!(!names_index_8(&without), "{without:?}");
    let with = arr30_messages_with_msvc_cdb("forced.c", Some("/I ../sdk /FImsvc_idx.h"));
    assert!(names_index_8(&with), "{with:?}");
}

/// The same forced include with no `/I` at all: the header sits beside the
/// build, named by a path relative to the entry's directory.
#[test]
fn msvc_forced_include_resolves_with_no_include_path() {
    let with = arr30_messages_with_msvc_cdb("forced.c", Some("/FI../sdk/msvc_idx.h"));
    assert!(names_index_8(&with), "{with:?}");
}

#[test]
fn msvc_undefine_removes_a_define() {
    let msgs = arr30_messages_with_msvc_cdb("define.c", Some("/DIDX=8 /UIDX"));
    assert!(!names_index_8(&msgs), "{msgs:?}");
}

/// A file-local check macro that calls the file's own static exit helper is a
/// guard after `-I` header resolution too: resolve_includes rebuilds the
/// abort-check-macro table, and that rebuild must also see main.c's static
/// die(). Without -I only the first build runs, which the EXP34-C fixture
/// covers.
#[test]
fn check_macro_calling_a_static_exit_helper_survives_include_resolution() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cli/check_macro_static_exit_helper");
    let src = dir.join("src");
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules_templates/rules-all.toml");
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out.json");
    let (code, _, stderr) = run_aurora_lint(&[
        src.to_str().unwrap(),
        "-d",
        src.to_str().unwrap(),
        "-I",
        dir.join("include").to_str().unwrap(),
        "-m",
        manifest.to_str().unwrap(),
        "--rules",
        "EXP34-C",
        "-j",
        "1",
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let exp34: Vec<_> = violations
        .iter()
        .filter(|v| v["rule_id"] == "EXP34-C")
        .collect();
    assert!(exp34.is_empty(), "{violations:?}");
}

#[test]
fn msvc_database_matches_include_names_ignoring_case() {
    // `<MSVC_Idx.H>` names sdk/msvc_idx.h only to a toolchain that ignores
    // case. A cl database declares one, so the header is read and the index
    // it defines gates the finding.
    let (with, output) =
        arr30_scan_with_msvc_cdb("case.c", Some("/I../sdk"), &["--report-macro-gaps"]);
    assert!(names_index_8(&with), "{with:?}");
    assert!(
        output.contains("spelled in a different case") && output.contains("MSVC_Idx.H"),
        "{output}"
    );
    // An explicit setting wins over what the database implies. Exact
    // matching takes the file system's answer, so this half needs one that
    // matches case (not macOS APFS or drvfs).
    if temp_fs_ignores_case() {
        eprintln!("exact-mode half skipped: the temporary directory's file system ignores case");
        return;
    }
    let (exact, _) =
        arr30_scan_with_msvc_cdb("case.c", Some("/I../sdk"), &["--include-names", "exact"]);
    assert!(!names_index_8(&exact), "{exact:?}");
}

/// Whether the file system temporary directories live on ignores case,
/// probed by creating `A` and looking for `a`.
fn temp_fs_ignores_case() -> bool {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("A"), "").unwrap();
    dir.path().join("a").exists()
}

#[test]
fn msvc_database_names_include_matching_in_the_settings() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("compile_commands.json");
    std::fs::write(
        &db,
        serde_json::json!([{
            "directory": dir.path().to_str().unwrap(),
            "file": "a.c",
            "command": r"C:\VS\bin\cl.exe /nologo -c a.c",
        }])
        .to_string(),
    )
    .unwrap();
    let current = |extra: &[&str]| {
        let mut args = vec!["--list-options", "json"];
        args.extend_from_slice(extra);
        let (code, stdout, stderr) = run_aurora_lint(&args);
        assert_eq!(code, 0, "{stderr}");
        let listing: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        listing["current"].clone()
    };
    let plain = current(&[]);
    let cl = current(&["--compile-commands", db.to_str().unwrap()]);
    assert!(plain["include_names"].is_null());
    assert_eq!(cl["include_names"], "case-insensitive");
    assert_eq!(cl["preset"], "default");
    assert_ne!(cl["hash"], plain["hash"]);
}

#[test]
fn case_mismatch_is_reported_without_any_search_path() {
    // No -I and no database: only the per-file audit sees the include, and
    // it still names the spelling cl's rule tolerates.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("local.h"), "#define LOCAL 1\n").unwrap();
    let src = dir.path().join("a.c");
    std::fs::write(&src, "#include \"Local.H\"\nint a = LOCAL;\n").unwrap();
    let scan = |names: &str| {
        let (code, stdout, stderr) = run_aurora_lint(&[
            src.to_str().unwrap(),
            "-m",
            fixtures().join("manifest_arr30.toml").to_str().unwrap(),
            "--include-names",
            names,
            "--report-macro-gaps",
        ]);
        assert_eq!(code, 0, "{stderr}");
        format!("{stdout}{stderr}")
    };
    let cl = scan("case-insensitive");
    assert!(
        cl.contains("spelled in a different case") && cl.contains("Local.H"),
        "{cl}"
    );
    let exact = scan("exact");
    assert!(!exact.contains("spelled in a different case"), "{exact}");
}

/// Scan a project of `files` (name, contents) written to a fresh directory,
/// with the project prescan (`-d`) over the same directory, under `rules`;
/// return the finding lines.
fn scan_project(files: &[(&str, &str)], rules: &str) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    for (name, contents) in files {
        std::fs::write(dir.path().join(name), contents).unwrap();
    }
    let root = dir.path().to_str().unwrap();
    let (_, stdout, stderr) = run_aurora_lint(&[root, "-d", root, "--rules", rules]);
    assert!(!stderr.contains("error"), "stderr: {stderr}");
    stdout
        .lines()
        .filter(|l| l.contains("] ") && l.contains("-C: "))
        .map(str::to_string)
        .collect()
}

#[test]
fn a_files_own_macro_decides_whether_it_reads_an_argument() {
    // a.c's TRACE drops its argument; b.c's reads it. In b.c, TRACE(w)
    // reads the uninitialized w whichever file the prescan met first.
    for (first, second) in [("a.c", "b.c"), ("b.c", "a.c")] {
        let dropping = "#define TRACE(v) 0\nvoid f(void) { int u = 0; TRACE(u); }\n";
        let reading =
            "void log_int(int);\n#define TRACE(v) log_int(v)\nvoid g(void) { int w; TRACE(w); }\n";
        let found = scan_project(&[(first, dropping), (second, reading)], "EXP33-C");
        assert!(
            found
                .iter()
                .any(|l| l.contains(second) && l.contains("'w'")),
            "{found:?}"
        );
    }
}

#[test]
fn a_c_files_private_alias_is_not_another_files_alternative() {
    // h.h makes XFREE free for everyone who includes it; a.c redefines it
    // privately. c.c's XFREE(p) is still free, so p does not leak.
    let found = scan_project(
        &[
            ("h.h", "#include <stdlib.h>\n#define XFREE free\n"),
            (
                "a.c",
                "#include \"h.h\"\nvoid my_free(void *);\n#undef XFREE\n#define XFREE my_free\n\
                 void a(void *q) { XFREE(q); }\n",
            ),
            (
                "c.c",
                "#include \"h.h\"\nvoid c(void) { char *p = malloc(4); if (p) p[0] = 0; XFREE(p); }\n",
            ),
        ],
        "MEM31-C",
    );
    assert!(!found.iter().any(|l| l.contains("c.c")), "{found:?}");
}

#[test]
fn a_c_files_private_macro_is_not_another_files_alternative() {
    // Each .c file defines GET privately; b.c's is not a build of a.c's,
    // so a.c's GET still writes `v`.
    let found = scan_project(
        &[
            (
                "a.c",
                "int read_val(void);\n#define GET(out) ((out) = read_val())\n\
                 int f(void) { int v; GET(v); return v; }\n",
            ),
            (
                "b.c",
                "void log_get(int);\n#define GET(out) log_get(out)\n\
                 void g(void) { int w = 0; GET(w); }\n",
            ),
        ],
        "EXP33-C",
    );
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_headers_noreturn_keyword_survives_a_definition_ending_in_another_files_noreturn() {
    // die.c cannot see that bail() never returns, but die.h says die()
    // does not, and nothing in die()'s body comes back on its own: the
    // path through die() ends, so `p` is not used after the free.
    let found = scan_project(
        &[
            (
                "die.h",
                "_Noreturn void bail(int code);\n_Noreturn void die(const char *m);\n",
            ),
            (
                "bail.c",
                "#include <stdlib.h>\nvoid bail(int code) { exit(code); }\n",
            ),
            (
                "die.c",
                "void log_msg(const char *);\n\
                 void die(const char *m) { log_msg(m); bail(1); }\n",
            ),
            (
                "main.c",
                "#include <stdlib.h>\n#include \"die.h\"\n\
                 void h(char *p, int x) { if (x) { free(p); die(\"x\"); } p[0] = 1; }\n",
            ),
        ],
        "MEM30-C",
    );
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_definition_in_another_file_that_returns_keeps_the_path() {
    // One program's fatal() aborts, another's returns: the name is not
    // noreturn for the caller, which uses `p` after the free in the build
    // linked with the second.
    let found = scan_project(
        &[
            (
                "hard.c",
                "#include <stdlib.h>\nvoid fatal(void) { abort(); }\n",
            ),
            (
                "soft.c",
                "void log_msg(const char *);\n\
                 void fatal(void) { log_msg(\"x\"); return; }\n",
            ),
            (
                "main.c",
                "#include <stdlib.h>\nvoid fatal(void);\n\
                 void h(char *p, int x) { if (x) { free(p); fatal(); } p[0] = 1; }\n",
            ),
        ],
        "MEM30-C",
    );
    assert_eq!(found.len(), 1, "{found:?}");
}

fn manifest_pre31() -> PathBuf {
    fixtures().join("manifest_pre31.toml")
}

/// PRE31-C findings for `main.c` in one `crossfile_pre31` project, whose
/// macro is defined in a header the prescan reads.
fn pre31_crossfile_violations(case: &str) -> Vec<serde_json::Value> {
    let project = fixtures().join("crossfile_pre31").join(case);
    let project = project.to_str().unwrap();
    pre31_violations(&format!("{project}/main.c"), &["-d", project])
}

/// PRE31-C findings for one file, with `extra` arguments.
fn pre31_violations(file: &str, extra: &[&str]) -> Vec<serde_json::Value> {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let manifest = manifest_pre31();
    let mut args = vec![file, "-m", manifest.to_str().unwrap()];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["-e", out.to_str().unwrap()]);
    let (code, _, stderr) = run_aurora_lint(&args);
    assert_eq!(code, 0, "{stderr}");
    serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap()
}

/// A header's macro is judged by every `#if` arm it has, as one defined in
/// the calling file is: `DBG_COUNT`'s first arm evaluates its argument once,
/// but the release arm drops it, so `DBG_COUNT(n++)` is reportable.
#[test]
fn pre31_header_macro_judged_by_every_arm() {
    let violations = pre31_crossfile_violations("dropped_in_one_arm");
    assert_eq!(violations.len(), 1, "{:?}", violations);
    assert_eq!(violations[0]["rule_id"], "PRE31-C");
}

/// The control: every arm of the header's macro evaluates its argument
/// exactly once.
#[test]
fn pre31_header_macro_evaluating_once_in_every_arm_is_clean() {
    let violations = pre31_crossfile_violations("once_in_every_arm");
    assert!(violations.is_empty(), "{:?}", violations);
}

/// A `#define` in another .c file is live only in that translation unit:
/// `a.c`'s own `TWICE` evaluates its argument twice, but `main.c` gets
/// `util.h`'s, which evaluates it once.
#[test]
fn pre31_macro_defined_in_another_c_file_does_not_apply() {
    let violations = pre31_crossfile_violations("unrelated_c_file");
    assert!(violations.is_empty(), "{:?}", violations);
}

/// A header found only through `-I` is judged by every arm, as one in a
/// scanned directory is.
#[test]
fn pre31_header_on_include_path_judged_by_every_arm() {
    let project = fixtures().join("crossfile_pre31/include_path");
    let src = project.join("src");
    let include = project.join("include");
    let violations = pre31_violations(
        src.join("main.c").to_str().unwrap(),
        &["-d", src.to_str().unwrap(), "-I", include.to_str().unwrap()],
    );
    assert_eq!(violations.len(), 1, "{:?}", violations);
}

/// The arms survive a prescan cache round trip: a scan from the saved
/// context reports what the scan that saved it did.
#[test]
fn pre31_header_macro_arms_survive_prescan_cache() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("prescan.bin");
    let cache = cache.to_str().unwrap();
    let project = fixtures().join("crossfile_pre31/dropped_in_one_arm");
    let main_c = project.join("main.c");
    let saved = pre31_violations(
        main_c.to_str().unwrap(),
        &["-d", project.to_str().unwrap(), "--save-prescan", cache],
    );
    let loaded = pre31_violations(main_c.to_str().unwrap(), &["--load-prescan", cache]);
    assert_eq!(saved.len(), 1, "{:?}", saved);
    assert_eq!(loaded, saved);
}

/// Scan one `declared_memory/` fixture under `manifest` with `args` appended;
/// return each finding as `(rule, line, message)`.
fn declared_memory_findings(
    file: &str,
    manifest: &str,
    args: &[&str],
) -> Vec<(String, u64, String)> {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let path = fixtures().join("declared_memory").join(file);
    let manifest = fixtures().join(manifest);
    let mut all = vec![
        path.to_str().unwrap(),
        "-m",
        manifest.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ];
    all.extend(args);
    let (code, _, stderr) = run_aurora_lint(&all);
    assert!(code == 0 || code == 1, "stderr: {stderr}");
    let findings: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    findings
        .iter()
        .map(|f| {
            (
                f["rule_id"].as_str().unwrap().to_string(),
                f["line"].as_u64().unwrap(),
                f["message"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn has(findings: &[(String, u64, String)], rule: &str, line: u64, text: &str) -> bool {
    findings
        .iter()
        .any(|(r, l, m)| r == rule && *l == line && m.contains(text))
}

#[test]
fn an_undeclared_hook_is_not_a_free_and_a_declared_one_is() {
    let bare = declared_memory_findings("hook_releases.c", "manifest_mem30_mem31.toml", &[]);
    assert!(
        bare.iter()
            .any(|(r, _, m)| r == "MEM31-C" && m.contains("not freed")),
        "an undeclared hook proves nothing, so the block leaks: {bare:?}"
    );
    let declared =
        declared_memory_findings("hook_releases.c", "manifest_declared_memory.toml", &[]);
    assert!(declared.is_empty(), "{declared:?}");
    // The command line says the same as the manifest.
    let cli = declared_memory_findings(
        "hook_releases.c",
        "manifest_mem30_mem31.toml",
        &["--deallocator", "platform_give_back"],
    );
    assert!(cli.is_empty(), "{cli:?}");
}

#[test]
fn a_declared_deallocator_accuses_as_well_as_excuses() {
    let bare = declared_memory_findings("hook_double_free.c", "manifest_mem30_mem31.toml", &[]);
    assert!(
        !bare.iter().any(|(_, _, m)| m.contains("ouble")),
        "an undeclared hook is no free to double: {bare:?}"
    );
    let declared =
        declared_memory_findings("hook_double_free.c", "manifest_declared_memory.toml", &[]);
    assert!(has(&declared, "MEM31-C", 7, "Double free"), "{declared:?}");
    assert!(has(&declared, "MEM30-C", 7, "Double-free"), "{declared:?}");
}

#[test]
fn a_wrapper_around_a_declared_hook_frees_by_its_summary() {
    let declared = declared_memory_findings(
        "wrapper_use_after_free.c",
        "manifest_declared_memory.toml",
        &[],
    );
    assert!(
        has(&declared, "MEM30-C", 11, "Use-after-free"),
        "{declared:?}"
    );
    let bare =
        declared_memory_findings("wrapper_use_after_free.c", "manifest_mem30_mem31.toml", &[]);
    assert!(!has(&bare, "MEM30-C", 11, "Use-after-free"), "{bare:?}");
}

#[test]
fn a_declared_deallocator_frees_only_the_argument_it_names() {
    let declared = declared_memory_findings(
        "pool_put_second_argument.c",
        "manifest_declared_memory.toml",
        &[],
    );
    assert!(has(&declared, "MEM31-C", 11, "'p'"), "{declared:?}");
    assert!(
        !declared.iter().any(|(_, _, m)| m.contains("'pool'")),
        "the pool is not freed: {declared:?}"
    );
    assert!(
        !declared.iter().any(|(_, _, m)| m.contains("not freed")),
        "{declared:?}"
    );
}

#[test]
fn exp33_classifies_an_aliased_call_by_the_declared_allocator_it_names() {
    let declared = declared_memory_findings(
        "aliased_declared_allocator.c",
        "manifest_exp33_declared_memory.toml",
        &[],
    );
    assert!(
        has(&declared, "EXP33-C", 10, "uninitialized"),
        "take is pool_take, a declared malloc: {declared:?}"
    );
    assert!(
        !has(&declared, "EXP33-C", 15, ""),
        "take_zeroed is pool_take_zeroed, a declared calloc: {declared:?}"
    );
    let bare = declared_memory_findings("aliased_declared_allocator.c", "manifest_exp33.toml", &[]);
    assert!(
        !bare.iter().any(|(r, _, _)| r == "EXP33-C"),
        "an undeclared function allocates nothing: {bare:?}"
    );
}

#[test]
fn exp33_reads_a_wrapper_as_an_allocator_only_once_it_is_declared() {
    // The CERT wiki's EXP33-C realloc example (the rule's expected_fail
    // fixture): `resize_array` wraps realloc, so its new elements are
    // uninitialized, but only a declaration says what it returns.
    let declared = declared_memory_findings(
        "declared_realloc_wrapper.c",
        "manifest_exp33_declared_memory.toml",
        &[],
    );
    assert!(
        has(&declared, "EXP33-C", 36, "uninitialized"),
        "resize_array is declared to follow realloc: {declared:?}"
    );
    let bare = declared_memory_findings("declared_realloc_wrapper.c", "manifest_exp33.toml", &[]);
    assert!(
        !bare.iter().any(|(r, _, _)| r == "EXP33-C"),
        "an undeclared wrapper allocates nothing: {bare:?}"
    );
}

#[test]
fn declared_allocators_allocate_and_a_realloc_like_one_releases_its_old_block() {
    let declared =
        declared_memory_findings("pool_allocators.c", "manifest_declared_memory.toml", &[]);
    assert!(
        has(&declared, "MEM31-C", 7, "'pool_take'"),
        "a declared allocator's block must be freed: {declared:?}"
    );
    assert!(
        has(&declared, "MEM30-C", 17, "Use-after-free"),
        "pool_grow follows realloc, which releases the old block: {declared:?}"
    );
    let bare = declared_memory_findings("pool_allocators.c", "manifest_mem30_mem31.toml", &[]);
    assert!(!has(&bare, "MEM31-C", 7, "'pool_take'"), "{bare:?}");
    assert!(!has(&bare, "MEM30-C", 17, "Use-after-free"), "{bare:?}");
}

#[test]
fn declarations_are_recorded_in_the_settings_and_their_hash() {
    let bare = sarif_settings(&manifest_msc04(), &[]);
    let declared = sarif_settings(
        &manifest_msc04(),
        &[
            "--deallocator",
            "pool_put=2",
            "--allocator",
            "pool_grow=realloc",
        ],
    );
    assert!(bare["deallocators"].is_null());
    assert_eq!(declared["deallocators"]["pool_put"], 2);
    assert_eq!(declared["allocators"]["pool_grow"], "realloc");
    assert_eq!(declared["preset"], "default");
    assert_ne!(declared["hash"], bare["hash"]);
}

#[test]
fn an_invalid_declaration_is_refused() {
    let path = fixtures().join("declared_memory/hook_releases.c");
    let manifest = fixtures().join("manifest_mem30_mem31.toml");
    for args in [
        ["--deallocator", "free=2"],
        ["--deallocator", "pool_put=0"],
        ["--allocator", "pool_take=new"],
    ] {
        let mut all = vec![path.to_str().unwrap(), "-m", manifest.to_str().unwrap()];
        all.extend(args);
        let (code, _, stderr) = run_aurora_lint(&all);
        assert_eq!(code, 2, "{args:?} should be refused; stderr: {stderr}");
    }
}

#[test]
fn a_prescan_cache_built_under_other_declarations_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("prescan.bin");
    let path = fixtures().join("declared_memory/hook_releases.c");
    let manifest = fixtures().join("manifest_mem30_mem31.toml");
    let (code, _, stderr) = run_aurora_lint(&[
        path.to_str().unwrap(),
        "-m",
        manifest.to_str().unwrap(),
        "--save-prescan",
        cache.to_str().unwrap(),
    ]);
    assert!(code == 0 || code == 1, "stderr: {stderr}");
    let load = |extra: &[&str]| {
        let mut all = vec![
            path.to_str().unwrap(),
            "-m",
            manifest.to_str().unwrap(),
            "--load-prescan",
            cache.to_str().unwrap(),
        ];
        all.extend(extra);
        run_aurora_lint(&all)
    };
    let (code, _, stderr) = load(&[]);
    assert!(code == 0 || code == 1, "same declarations load: {stderr}");
    let (code, _, stderr) = load(&["--deallocator", "platform_give_back"]);
    assert_eq!(code, 2, "stderr: {stderr}");
    assert!(stderr.contains("declarations"), "{stderr}");
}

#[test]
fn an_alias_frees_only_where_every_arm_frees_the_same_argument() {
    let leaks = |args: &[&str]| {
        declared_memory_findings("two_arm_alias.c", "manifest_mem30_mem31.toml", args)
            .into_iter()
            .any(|(r, _, m)| r == "MEM31-C" && m.contains("not freed"))
    };
    assert!(leaks(&[]), "an undeclared arm proves nothing");
    assert!(!leaks(&["--deallocator", "HOOK_FREE"]));
    // The hook frees its second argument and `free` its first: the arms
    // disagree, so no build-independent free is proven.
    assert!(leaks(&["--deallocator", "HOOK_FREE=2"]));
}

#[test]
fn one_arm_that_is_a_declared_hook_accuses_a_double_free() {
    let double = |args: &[&str]| {
        has(
            &declared_memory_findings(
                "two_arm_hook_double_free.c",
                "manifest_mem30_mem31.toml",
                args,
            ),
            "MEM30-C",
            15,
            "Double-free",
        )
    };
    assert!(!double(&[]), "no arm is a known free");
    assert!(double(&["--deallocator", "HOOK_FREE"]));
}

#[test]
fn a_profile_keeps_the_manifests_declared_memory_functions() {
    // A preset chooses policy; what the project's own functions do survives
    // it, in the scan and in the settings it reports and hashes.
    let with_profile = declared_memory_findings(
        "hook_releases.c",
        "manifest_declared_memory.toml",
        &["--profile", "default"],
    );
    assert!(with_profile.is_empty(), "{with_profile:?}");
    let manifest = fixtures().join("manifest_declared_memory.toml");
    let options = |m: &str| {
        let (code, stdout, stderr) =
            run_aurora_lint(&["--list-options", "json", "--profile", "strict", "-m", m]);
        assert_eq!(code, 0, "stderr: {stderr}");
        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        json["current"].clone()
    };
    let declared = options(manifest.to_str().unwrap());
    assert_eq!(declared["deallocators"]["platform_give_back"], 1);
    assert_eq!(declared["allocators"]["pool_grow"], "realloc");
    let plain = options(
        fixtures()
            .join("manifest_mem30_mem31.toml")
            .to_str()
            .unwrap(),
    );
    assert!(plain["deallocators"].is_null(), "{plain}");
    assert_ne!(declared["hash"], plain["hash"]);
}

#[test]
fn a_leak_through_a_two_arm_allocator_names_the_standard_allocator() {
    let found = declared_memory_findings(
        "two_arm_allocator.c",
        "manifest_mem30_mem31.toml",
        &["--allocator", "HOOK_CALLOC=calloc"],
    );
    let leaks: Vec<_> = found.iter().filter(|(r, _, _)| r == "MEM31-C").collect();
    assert!(!leaks.is_empty(), "{found:?}");
    assert!(
        leaks.iter().all(|(_, _, m)| m.contains("'calloc'")),
        "{found:?}"
    );
}

// ---- Scope: --exclude, --report-exclude, --prescan-exclude ----------------

/// A tree where `tests/stub.c` holds the only definition of `rel`, which
/// frees its argument, and a use-after-free of its own; `src/a.c` uses a
/// pointer after `rel(p)`. MEM30-C reports a.c only when the stub fed the
/// prescan, and the stub only when it was scanned.
fn write_scope_tree(dir: &std::path::Path) {
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::create_dir_all(dir.join("tests")).unwrap();
    std::fs::write(
        dir.join("src/a.c"),
        "#include <stdlib.h>\nvoid rel(void *p);\n\
         void f(void) { char *p = malloc(4); if (!p) return; rel(p); p[0] = 1; }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("tests/stub.c"),
        "#include <stdlib.h>\nvoid rel(void *p) { free(p); }\n\
         void g(void) { char *q = malloc(4); if (!q) return; free(q); q[0] = 1; }\n",
    )
    .unwrap();
}

/// Which of the two files MEM30-C reports in, scanning the tree with `args`.
fn mem30_files_under(dir: &std::path::Path, args: &[&str]) -> (bool, bool) {
    let root = dir.to_str().unwrap();
    let mut all = vec![root, "-d", root, "--rules", "MEM30-C"];
    all.extend_from_slice(args);
    let (code, stdout, stderr) = run_aurora_lint(&all);
    assert_eq!(code, 0, "stderr: {stderr}");
    let reported = |file: &str| {
        stdout
            .lines()
            .any(|l| l.contains(file) && l.contains("MEM30-C"))
    };
    (reported("a.c"), reported("stub.c"))
}

#[test]
fn exclude_all_leaves_a_tree_out_of_findings_and_cross_file_facts() {
    let dir = tempfile::tempdir().unwrap();
    write_scope_tree(dir.path());
    assert_eq!(mem30_files_under(dir.path(), &[]), (true, true));
    assert_eq!(
        mem30_files_under(dir.path(), &["--exclude-all", "tests/**"]),
        (false, false)
    );
}

#[test]
fn report_exclude_keeps_a_tree_feeding_cross_file_facts() {
    let dir = tempfile::tempdir().unwrap();
    write_scope_tree(dir.path());
    assert_eq!(
        mem30_files_under(dir.path(), &["--report-exclude", "tests/**"]),
        (true, false)
    );
}

#[test]
fn prescan_exclude_still_reports_a_tree_it_keeps_out_of_cross_file_facts() {
    let dir = tempfile::tempdir().unwrap();
    write_scope_tree(dir.path());
    assert_eq!(
        mem30_files_under(dir.path(), &["--prescan-exclude", "tests/**"]),
        (false, true)
    );
}

/// A tree where `tests/inc/impl.h` holds the only definition of `rel2`,
/// which frees its argument, and only `tests/t.c` includes it; `src/use.c`
/// sees a prototype and uses a pointer after `rel2(p)`. With `-I tests/inc`,
/// include resolution reaches the header only through t.c -- unless
/// `use_includes` makes use.c include it too.
fn write_include_scope_tree(dir: &std::path::Path, use_includes: bool) {
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::create_dir_all(dir.join("tests/inc")).unwrap();
    let include = if use_includes {
        "#include \"impl.h\"\n"
    } else {
        ""
    };
    std::fs::write(
        dir.join("src/use.c"),
        format!("{include}void rel2(char *p);\nvoid use(char *p) {{ rel2(p); p[0] = 1; }}\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("tests/inc/impl.h"),
        "#include <stdlib.h>\nvoid rel2(char *p) { free(p); }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("tests/t.c"),
        "#include \"impl.h\"\nint main(void) { return 0; }\n",
    )
    .unwrap();
}

/// Whether MEM30-C reports use.c, scanning the tree with `-I tests/inc`,
/// with or without `-d`, plus `args`.
fn mem30_in_use_c_with_include_path(dir: &std::path::Path, with_d: bool, args: &[&str]) -> bool {
    let root = dir.to_str().unwrap();
    let inc = dir.join("tests/inc");
    let mut all = vec![root, "--rules", "MEM30-C", "-I", inc.to_str().unwrap()];
    if with_d {
        all.extend_from_slice(&["-d", root]);
    }
    all.extend_from_slice(args);
    let (code, stdout, stderr) = run_aurora_lint(&all);
    assert_eq!(code, 0, "stderr: {stderr}");
    stdout
        .lines()
        .any(|l| l.contains("use.c") && l.contains("MEM30-C"))
}

#[test]
fn an_excluded_file_is_no_includer_for_include_resolution() {
    let dir = tempfile::tempdir().unwrap();
    write_include_scope_tree(dir.path(), false);
    for with_d in [true, false] {
        assert!(mem30_in_use_c_with_include_path(dir.path(), with_d, &[]));
        for flag in ["--exclude-all", "--prescan-exclude"] {
            assert!(
                !mem30_in_use_c_with_include_path(dir.path(), with_d, &[flag, "tests/**"]),
                "{flag} (with -d: {with_d}) let the excluded t.c's header in"
            );
        }
    }
}

#[test]
fn a_header_an_in_scope_file_includes_is_read_though_its_tree_is_excluded() {
    let dir = tempfile::tempdir().unwrap();
    write_include_scope_tree(dir.path(), true);
    for with_d in [true, false] {
        assert!(mem30_in_use_c_with_include_path(
            dir.path(),
            with_d,
            &["--exclude-all", "tests/**"]
        ));
    }
}

/// Scan the scope tree with `args` (and a `toolchain.toml` ignoring
/// `tests/**` when `toolchain`), exporting SARIF: the run's recorded
/// settings, stdout and stderr.
fn scope_tree_run(toolchain: bool, args: &[&str]) -> (serde_json::Value, String, String) {
    let dir = tempfile::tempdir().unwrap();
    write_scope_tree(dir.path());
    if toolchain {
        std::fs::write(
            dir.path().join("toolchain.toml"),
            "[ignore]\npaths = [\"tests/**\"]\n",
        )
        .unwrap();
    }
    let out = dir.path().join("out.sarif");
    let root = dir.path().to_str().unwrap();
    let mut all = vec![
        root,
        "-d",
        root,
        "--rules",
        "MEM30-C",
        "-e",
        out.to_str().unwrap(),
    ];
    all.extend_from_slice(args);
    let (code, stdout, stderr) = run_aurora_lint(&all);
    assert_eq!(code, 0, "stderr: {stderr}");
    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    (
        sarif["runs"][0]["properties"]["aurora-lint/settings"].clone(),
        stdout,
        stderr,
    )
}

fn reports(stdout: &str, file: &str) -> bool {
    stdout
        .lines()
        .any(|l| l.contains(file) && l.contains("MEM30-C"))
}

#[test]
fn a_toolchain_ignore_keeps_its_report_only_meaning_and_the_hash() {
    // toolchain.toml's ignores always meant "no findings here"; they still
    // feed cross-file facts, so neither the findings elsewhere nor the
    // settings identity change.
    let (plain, _, _) = scope_tree_run(false, &[]);
    let (ignored, stdout, _) = scope_tree_run(true, &[]);
    assert!(reports(&stdout, "a.c"), "{stdout}");
    assert!(!reports(&stdout, "stub.c"), "{stdout}");
    assert_eq!(ignored["prescan_scope"], serde_json::Value::Null);
    assert_eq!(ignored["hash"], plain["hash"]);
}

#[test]
fn deprecated_exclude_means_report_exclude_and_says_so() {
    let (deprecated, dep_out, dep_err) = scope_tree_run(false, &["--exclude", "tests/**"]);
    let (report, rep_out, rep_err) = scope_tree_run(false, &["--report-exclude", "tests/**"]);
    let findings = |out: &str| (reports(out, "a.c"), reports(out, "stub.c"));
    assert_eq!(findings(&dep_out), (true, false), "{dep_out}");
    assert_eq!(findings(&dep_out), findings(&rep_out));
    assert_eq!(deprecated["hash"], report["hash"]);
    // ...which is the hash of a scan that leaves nothing out.
    let (plain, _, _) = scope_tree_run(false, &[]);
    assert_eq!(report["hash"], plain["hash"]);
    assert!(
        dep_err.contains("--exclude is deprecated") && dep_err.contains("--exclude-all"),
        "stderr: {dep_err}"
    );
    assert!(!rep_err.contains("deprecated"), "stderr: {rep_err}");
}

#[test]
fn exclude_all_moves_the_settings_hash() {
    let (plain, _, _) = scope_tree_run(false, &[]);
    let (all, _, _) = scope_tree_run(false, &["--exclude-all", "tests/**"]);
    assert_eq!(all["prescan_scope"], serde_json::json!(["tests/**"]));
    assert_ne!(all["hash"], plain["hash"]);
}

#[test]
fn manifest_scope_table_adds_to_the_command_line() {
    let dir = tempfile::tempdir().unwrap();
    write_scope_tree(dir.path());
    let manifest = dir.path().join("rules.toml");
    std::fs::write(
        &manifest,
        "[metadata]\nname = \"scope\"\nversion = \"1\"\ncert_version = \"2016\"\n\n\
         [scope]\nexclude_all = [\"tests/**\"]\n\n\
         [rules.cert_c.MEM30-C]\nenabled = true\n",
    )
    .unwrap();
    assert_eq!(
        mem30_files_under(dir.path(), &["-m", manifest.to_str().unwrap()]),
        (false, false)
    );
}

/// A prescan cache records which files it was built without, and a scan
/// that leaves out others refuses it rather than reading definitions the
/// scan excludes.
#[test]
fn a_prescan_cache_is_refused_under_a_different_scope() {
    let dir = tempfile::tempdir().unwrap();
    write_scope_tree(dir.path());
    let root = dir.path().to_str().unwrap();
    let cache = dir.path().join("prescan.bin");
    let cache = cache.to_str().unwrap();
    let (code, _, stderr) = run_aurora_lint(&[
        root,
        "-d",
        root,
        "--rules",
        "MEM30-C",
        "--save-prescan",
        cache,
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let (code, _, stderr) = run_aurora_lint(&[
        root,
        "--rules",
        "MEM30-C",
        "--load-prescan",
        cache,
        "--exclude-all",
        "tests/**",
    ]);
    assert_ne!(code, 0);
    assert!(
        stderr
            .contains(r#"prescan_scope = (none), but this run uses prescan_scope = ["tests/**"]"#),
        "stderr: {stderr}"
    );
    let (code, _, stderr) = run_aurora_lint(&[root, "--rules", "MEM30-C", "--load-prescan", cache]);
    assert_eq!(code, 0, "stderr: {stderr}");

    // The reverse: a cache built leaving tests/ out is refused by a run that
    // leaves nothing out, and loads under the same prescan scope however it is
    // spelled.
    let (code, _, stderr) = run_aurora_lint(&[
        root,
        "-d",
        root,
        "--rules",
        "MEM30-C",
        "--exclude-all",
        "tests/**",
        "--save-prescan",
        cache,
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let (code, _, stderr) = run_aurora_lint(&[root, "--rules", "MEM30-C", "--load-prescan", cache]);
    assert_ne!(code, 0);
    assert!(
        stderr
            .contains(r#"prescan_scope = ["tests/**"], but this run uses prescan_scope = (none)"#),
        "stderr: {stderr}"
    );
    let (code, _, stderr) = run_aurora_lint(&[
        root,
        "--rules",
        "MEM30-C",
        "--load-prescan",
        cache,
        "--prescan-exclude",
        "tests/**",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
}

/// PRE31-C's findings in `fixture/project/file`, with the project
/// prescanned and `fixture/system` on the search path.
fn pre31_findings(fixture: &str, file: &str, extra: &[&str]) -> Vec<(u64, String)> {
    let system = fixtures().join(fixture).join("system");
    let mut args = vec!["-I", system.to_str().unwrap()];
    args.extend(extra);
    pre31_findings_searching(fixture, file, &args)
}

/// [`pre31_findings`] with only the search paths `extra` gives.
fn pre31_findings_searching(fixture: &str, file: &str, extra: &[&str]) -> Vec<(u64, String)> {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let project = fixtures().join(fixture).join("project");
    let mut argv: Vec<String> = vec![
        project.join(file).to_string_lossy().into_owned(),
        "-m".into(),
        fixtures()
            .join("manifest_pre31.toml")
            .to_string_lossy()
            .into_owned(),
        "-d".into(),
        project.to_string_lossy().into_owned(),
        "-e".into(),
        out.to_string_lossy().into_owned(),
    ];
    argv.extend(extra.iter().map(|s| s.to_string()));
    let args: Vec<&str> = argv.iter().map(String::as_str).collect();
    let (code, _, stderr) = run_aurora_lint(&args);
    assert_eq!(code, 0, "{stderr}");
    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    violations
        .iter()
        .filter(|v| v["rule_id"] == "PRE31-C")
        .map(|v| {
            (
                v["line"].as_u64().unwrap(),
                v["message"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn a_library_functions_own_macro_evaluates_each_argument_once() {
    // The system tolower reads its argument twice in its replacement list,
    // but C11 7.1.4 binds the implementation to evaluate it once. getc's
    // stream is the standard's own exception and stays reported.
    let found = pre31_findings("pre31_library_macro", "main.c", &[]);
    let lines: Vec<u64> = found.iter().map(|(l, _)| *l).collect();
    assert_eq!(lines, vec![11], "{found:?}");
    assert!(found[0].1.contains("'getc'"), "{found:?}");
}

#[test]
fn a_library_macro_is_judged_by_its_body_once_the_contract_is_withdrawn() {
    let found = pre31_findings(
        "pre31_library_macro",
        "main.c",
        &["--set", "library_macros_evaluate_once=false"],
    );
    let lines: Vec<u64> = found.iter().map(|(l, _)| *l).collect();
    assert_eq!(lines, vec![6, 11], "{found:?}");
}

#[test]
fn pedantic_withdraws_the_library_macro_contract_until_a_library_is_declared() {
    // Pedantic trusts only a declared C library; strict trusts the hosted one.
    let found = pre31_findings("pre31_library_macro", "main.c", &["--profile", "pedantic"]);
    assert_eq!(pre31_lines(&found), vec![6, 11], "{found:?}");
    let declared = pre31_findings(
        "pre31_library_macro",
        "main.c",
        &["--profile", "pedantic", "--libc", "glibc"],
    );
    let strict = pre31_findings("pre31_library_macro", "main.c", &["--profile", "strict"]);
    assert_eq!(pre31_lines(&declared), pre31_lines(&strict));
    assert_eq!(
        pre31_lines(&strict),
        pre31_lines(&pre31_findings("pre31_library_macro", "main.c", &[]))
    );
}

#[test]
fn a_project_macro_forwarding_to_a_library_macro_inherits_its_contract() {
    // LOWER hands c to the library's tolower, which evaluates it once; READ
    // hands f to getc, whose stream is the standard's exception.
    let found = pre31_findings("pre31_library_macro", "forward.c", &[]);
    assert_eq!(pre31_lines(&found), vec![10], "{found:?}");
    let withdrawn = pre31_findings(
        "pre31_library_macro",
        "forward.c",
        &["--set", "library_macros_evaluate_once=false"],
    );
    assert_eq!(pre31_lines(&withdrawn), vec![5, 10], "{withdrawn:?}");
}

#[test]
fn a_project_defined_library_name_is_judged_by_its_body() {
    let found = pre31_findings("pre31_own_library_name", "own.c", &[]);
    assert_eq!(pre31_lines(&found), vec![9], "{found:?}");
}

#[test]
fn a_project_macro_is_judged_by_the_header_its_file_includes() {
    // math_util.h and shapes.h define SQ two ways. stats.c includes the
    // first, which evaluates its argument twice; geometry.c reaches only the
    // second, through area.h, which evaluates it once.
    let stats = pre31_findings("pre31_include_closure", "stats.c", &[]);
    assert_eq!(
        stats.iter().map(|(l, _)| *l).collect::<Vec<_>>(),
        vec![7],
        "{stats:?}"
    );
    let geometry = pre31_findings("pre31_include_closure", "geometry.c", &[]);
    assert!(geometry.is_empty(), "{geometry:?}");
}

fn pre31_lines(found: &[(u64, String)]) -> Vec<u64> {
    found.iter().map(|(l, _)| *l).collect()
}

#[test]
fn with_no_search_path_every_definition_of_a_project_macro_counts() {
    // No -I, so no include graph: which header geometry.c compiles with is
    // unknown, and math_util.h's definition may be it.
    let found = pre31_findings_searching("pre31_include_closure", "geometry.c", &[]);
    assert_eq!(pre31_lines(&found), vec![5], "{found:?}");
}

#[test]
fn a_forced_include_is_in_every_files_closure() {
    // cl's /FI puts math_util.h ahead of geometry.c's first line, so its
    // definition of SQ is one the file may compile with.
    let dir = tempfile::tempdir().unwrap();
    let project = fixtures().join("pre31_include_closure").join("project");
    let db = dir.path().join("compile_commands.json");
    let entry = serde_json::json!([{
        "directory": project.to_str().unwrap(),
        "file": project.join("geometry.c").to_str().unwrap(),
        "command": format!(
            r"C:\VS\bin\Hostx64\x86\cl.exe /nologo /I{} /FImath_util.h -c geometry.c",
            project.to_str().unwrap()
        ),
    }]);
    std::fs::write(&db, entry.to_string()).unwrap();
    let found = pre31_findings_searching(
        "pre31_include_closure",
        "geometry.c",
        &["--compile-commands", db.to_str().unwrap()],
    );
    assert_eq!(pre31_lines(&found), vec![5], "{found:?}");
}

#[test]
fn an_include_that_did_not_resolve_keeps_the_definitions_it_may_name() {
    // main.c includes defs.h, whose definition of SQ evaluates its argument
    // twice, and shapes.h, whose definition evaluates it once. With only
    // system/ searched, defs.h does not resolve, but the prescan read it, so
    // its definition still counts; once inc/ is searched it resolves.
    let fixture = "pre31_partial_include";
    let project = fixtures().join(fixture).join("project");
    let inc = project.join("inc");
    for extra in [vec![], vec!["-I", inc.to_str().unwrap()]] {
        let found = pre31_findings(fixture, "main.c", &extra);
        assert_eq!(pre31_lines(&found), vec![6], "{extra:?}: {found:?}");
    }
    let unsearched = pre31_findings_searching(fixture, "main.c", &[]);
    assert_eq!(pre31_lines(&unsearched), vec![6], "{unsearched:?}");
}

#[test]
fn an_unresolved_relative_include_keeps_the_header_it_climbs_to() {
    // "../common/twice.h" does not resolve from sub/ with only system/
    // searched, but it names inc/common/twice.h, whose CUBE reads its
    // argument three times; with -I inc/any it resolves outright.
    let fixture = "pre31_partial_include";
    let found = pre31_findings(fixture, "sub/relative.c", &[]);
    assert_eq!(pre31_lines(&found), vec![6], "{found:?}");
    let any = fixtures().join(fixture).join("project/inc/any");
    let resolved = pre31_findings(fixture, "sub/relative.c", &["-I", any.to_str().unwrap()]);
    assert_eq!(pre31_lines(&resolved), vec![6], "{resolved:?}");
}

#[test]
fn a_computed_include_may_bring_any_definition() {
    // `#include WHICH_DEFS` names a header the scan cannot know, so inc/
    // defs.h's definition of SQ may be the one compiled.
    let found = pre31_findings("pre31_partial_include", "computed.c", &[]);
    assert_eq!(pre31_lines(&found), vec![7], "{found:?}");
}

#[test]
fn a_release_the_scan_cannot_read_is_a_free_only_once_declared() {
    let uaf = |args: &[&str]| {
        has(
            &declared_memory_findings("opaque_release.c", "manifest_mem30_mem31.toml", args),
            "MEM30-C",
            23,
            "Use-after-free",
        )
    };
    assert!(!uaf(&[]), "a `_free` name is not evidence of a free");
    assert!(uaf(&["--deallocator", "amalg_free"]));
}

#[test]
fn a_bodiless_deallocator_leaks_until_declared() {
    let leaks = |args: &[&str]| {
        declared_memory_findings("opaque_release.c", "manifest_mem30_mem31.toml", args)
            .into_iter()
            .any(|(r, _, m)| r == "MEM31-C" && m.contains("'b'"))
    };
    assert!(leaks(&[]));
    assert!(!leaks(&["--deallocator", "lib_obj_free"]));
}

#[test]
fn the_deallocator_candidate_report_names_a_bodiless_free_and_changes_no_finding() {
    let dir = tempfile::tempdir().unwrap();
    let path = fixtures().join("declared_memory").join("opaque_release.c");
    let manifest = fixtures().join("manifest_mem30_mem31.toml");
    let scan = |extra: &[&str]| {
        let out = dir.path().join("out.json");
        let mut args = vec![
            path.to_str().unwrap(),
            "-m",
            manifest.to_str().unwrap(),
            "-e",
            out.to_str().unwrap(),
        ];
        args.extend(extra);
        let (code, stdout, stderr) = run_aurora_lint(&args);
        assert!(code == 0 || code == 1, "stderr: {stderr}");
        let findings = std::fs::read_to_string(&out).unwrap();
        (findings, stdout)
    };
    let report = dir.path().join("candidates.json");
    let flag = format!("--report-deallocator-candidates={}", report.display());
    let (plain, _) = scan(&[]);
    let (reported, stdout) = scan(&[&flag]);
    assert_eq!(plain, reported, "the report must not change a finding");
    assert!(stdout.contains("[environment.deallocators]"), "{stdout}");
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
    let rows = json["candidates"].as_array().unwrap();
    // `amalg_free`'s body hands its one parameter to a function pointer, so
    // the block escapes and nothing leaks: it is not a candidate.
    assert_eq!(rows.len(), 1, "{json}");
    assert_eq!(rows[0]["callee"], "lib_obj_free");
    assert_eq!(rows[0]["argument"], 1);
    assert_eq!(rows[0]["count"], 1);
    assert_eq!(rows[0]["sample_line"], 35);
}

#[test]
fn a_realloc_wrapper_releases_its_argument_only_once_declared() {
    // CERT's MEM30-C noncompliant example: `gdRealloc` has no body in the
    // scan, and "realloc" in its name is not evidence.
    let uaf = |args: &[&str]| {
        has(
            &declared_memory_findings(
                "undeclared_realloc_wrapper.c",
                "manifest_mem30_mem31.toml",
                args,
            ),
            "MEM30-C",
            16,
            "Use-after-free",
        )
    };
    assert!(!uaf(&[]));
    assert!(uaf(&["--allocator", "gdRealloc=realloc"]));
}

#[test]
fn a_wrapper_over_an_alias_every_arm_frees_releases_its_argument() {
    let leaks = |args: &[&str]| {
        declared_memory_findings("two_arm_alias_wrapper.c", "manifest_mem30_mem31.toml", args)
            .into_iter()
            .any(|(r, _, m)| r == "MEM31-C" && m.contains("'p'"))
    };
    assert!(leaks(&[]), "an undeclared arm proves nothing");
    assert!(!leaks(&["--deallocator", "HOOK_FREE"]));
}

#[test]
fn every_definition_of_a_wrapper_over_an_alias_every_arm_frees_releases_its_argument() {
    let leaks = |args: &[&str]| {
        declared_memory_findings(
            "two_definition_alias_wrapper.c",
            "manifest_mem30_mem31.toml",
            args,
        )
        .into_iter()
        .any(|(r, _, m)| r == "MEM31-C" && m.contains("'p'"))
    };
    assert!(leaks(&[]), "an undeclared arm proves nothing");
    assert!(!leaks(&["--deallocator", "HOOK_FREE"]));
}

#[test]
fn each_allocation_into_one_variable_has_its_own_first_site() {
    // Two unchecked malloc() results reach `p` one after the other. Each is
    // its own value, so each is reported at its own first dereference; only
    // later sites of the same value are folded into its first.
    let found = scan_project(
        &[(
            "a.c",
            "#include <stdlib.h>\n\
             void f(void) {\n\
             \x20   char *p = malloc(10);\n\
             \x20   p[0] = 'x';\n\
             \x20   p[1] = 'y';\n\
             \x20   free(p);\n\
             \x20   p = malloc(20);\n\
             \x20   p[2] = 'a';\n\
             \x20   free(p);\n\
             }\n",
        )],
        "EXP34-C",
    );
    let lines: Vec<&str> = found.iter().filter_map(|l| l.split(':').nth(1)).collect();
    assert_eq!(lines, ["4", "8"], "{found:?}");
}

#[test]
fn a_later_null_test_reports_only_the_first_dereference_by_default() {
    // Each function dereferences `sta`, tests it, and dereferences it again.
    // The default policy reports the first dereference and folds the later
    // one into it; strict reports both.
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/rules/cert_c/EXP/EXP34-C/tests/fail/testcases_dereference_before_later_null_test.c"
    );
    let lines = |profile: &str| -> Vec<String> {
        let (_, stdout, _) =
            run_aurora_lint(&[fixture, "--rules", "EXP34-C", "--profile", profile]);
        stdout
            .lines()
            .filter(|l| l.contains("EXP34-C: "))
            .filter_map(|l| {
                l.rsplit(".c:")
                    .next()?
                    .split(':')
                    .next()
                    .map(str::to_string)
            })
            .collect()
    };
    assert_eq!(lines("default"), ["20", "32", "46"]);
    assert_eq!(lines("strict"), ["20", "26", "32", "39", "46", "50"]);
}

#[test]
fn a_compound_assignment_does_not_start_a_new_value() {
    // `p += 4` moves the same unchecked malloc() result along, so its later
    // use depends on the one missing check already reported at line 4.
    let found = scan_project(
        &[(
            "a.c",
            "#include <stdlib.h>\n\
             void f(void) {\n\
             \x20   char *p = malloc(10);\n\
             \x20   p[0] = 'x';\n\
             \x20   p += 4;\n\
             \x20   p[1] = 'y';\n\
             }\n",
        )],
        "EXP34-C",
    );
    let lines: Vec<&str> = found.iter().filter_map(|l| l.split(':').nth(1)).collect();
    assert_eq!(lines, ["4"], "{found:?}");
}

/// A directory scan of a deeply nested file plus any other file goes through
/// the parallel cross-file prescan on rayon's global pool, whose walks recurse
/// once per AST nesting level. A single-file scan, which every rule fixture
/// test is, never reaches that pool, so only a multi-file run can show the
/// pool's stack is big enough. The rule is immaterial: the prescan runs for
/// all of them. `RUST_MIN_STACK` is removed because `.cargo/config.toml` sets
/// it for everything cargo runs, which would hide the default a user's run
/// gets.
#[test]
fn multi_file_scan_of_deep_nesting_completes() {
    let dir = tempfile::tempdir().unwrap();
    let deep = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/rules/cert_c/MEM/MEM30-C/tests/pass/testcases_deep_if_nesting_stack_safety.c");
    std::fs::copy(&deep, dir.path().join("deep.c")).unwrap();
    std::fs::write(
        dir.path().join("other.c"),
        "int other(void) { return 0; }\n",
    )
    .unwrap();
    let output = Command::new(aurora_lint_bin())
        .args(["--rules", "ERR33-C", dir.path().to_str().unwrap()])
        .env_remove("RUST_MIN_STACK")
        .output()
        .expect("failed to execute aurora-lint");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "scan did not complete: {stderr}"
    );
}

/// The resolved settings `--list-options json` prints for `args`, or the
/// refusal text when they are invalid.
fn resolved_settings(args: &[&str]) -> Result<serde_json::Value, String> {
    let mut full = vec!["--list-options", "json"];
    full.extend_from_slice(args);
    let (code, stdout, stderr) = run_aurora_lint(&full);
    if code != 0 {
        return Err(stderr);
    }
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    Ok(json["current"].clone())
}

#[test]
fn an_integer_fact_overrides_the_data_model_and_enters_the_settings_hash() {
    let plain = resolved_settings(&["--data-model", "lp64"]).unwrap();
    let wide = resolved_settings(&["--data-model", "lp64", "--set", "int_bits=64"]).unwrap();
    let narrow = resolved_settings(&["--data-model", "lp64", "--set", "int_bits=16"]).unwrap();
    // A data model's own widths are named by the data model; only a declared override
    // is a key of its own.
    assert!(plain["int_bits"].is_null(), "{plain}");
    assert_eq!(narrow["int_bits"], 16, "{narrow}");
    assert_eq!(wide["int_bits"], 64, "{wide}");
    assert_eq!(narrow["data_model"], "lp64");
    // Every declared override changes the hash, and the same one does not.
    assert_ne!(plain["hash"], narrow["hash"]);
    assert_ne!(narrow["hash"], wide["hash"]);
    let again = resolved_settings(&["--data-model", "lp64", "--set", "int_bits=16"]).unwrap();
    assert_eq!(narrow["hash"], again["hash"]);
    // A yes/no fact is a boolean.
    let signed = resolved_settings(&["--set", "char_signed=true"]).unwrap();
    assert_eq!(signed["char_signed"], true, "{signed}");
}

#[test]
fn an_explicit_key_beats_the_data_model_whatever_the_order_and_the_command_line_beats_both() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("rules.toml");
    // The data model is named AFTER the override: the order of the lines is no part
    // of the precedence.
    std::fs::write(
        &manifest,
        "[metadata]\nname = \"t\"\nversion = \"1\"\ncert_version = \"2016\"\n\n\
         [environment]\nint_bits = 16\ndata_model = \"lp64\"\n\n[rules.cert_c]\n",
    )
    .unwrap();
    let m = manifest.to_str().unwrap();
    let from_manifest = resolved_settings(&["-m", m]).unwrap();
    assert_eq!(from_manifest["int_bits"], 16, "{from_manifest}");
    assert_eq!(from_manifest["data_model"], "lp64");
    let from_cli = resolved_settings(&["-m", m, "--set", "int_bits=64"]).unwrap();
    assert_eq!(from_cli["int_bits"], 64, "{from_cli}");
    // Repeating the data model's own value is the command line's to say, and still
    // beats the file's 16: the facts are the data model's, and so is the hash.
    let repeated = fact_values(&["-m", m, "--set", "int_bits=32"]);
    assert!(
        repeated.contains(&("int_bits".to_string(), "32".to_string())),
        "{repeated:?}"
    );
}

#[test]
fn a_width_below_the_iso_minimum_is_refused_naming_the_minimum() {
    for (fact, bits, minimum) in [
        ("short_bits", "8", "16"),
        ("int_bits", "8", "16"),
        ("long_bits", "16", "32"),
        ("long_long_bits", "32", "64"),
    ] {
        let err = resolved_settings(&["--set", &format!("{fact}={bits}")]).unwrap_err();
        assert!(
            err.contains(fact) && err.contains(&format!("below the {minimum} bits")),
            "{fact}: {err}"
        );
    }
}

#[test]
fn a_width_that_breaks_the_rank_order_is_refused() {
    let err = resolved_settings(&[
        "--data-model",
        "lp64",
        "--set",
        "int_bits=64",
        "--set",
        "long_bits=32",
    ])
    .unwrap_err();
    assert!(
        err.contains("int_bits = 64") && err.contains("ranks must not shrink"),
        "{err}"
    );
    // Only the widths that are known are ordered: int 64 over an unset long is
    // a configuration a project may mean.
    assert!(resolved_settings(&["--set", "int_bits=64"]).is_ok());
}

#[test]
fn an_unknown_fact_a_bad_value_and_an_unknown_data_model_are_each_refused() {
    let err = resolved_settings(&["--set", "int_bitz=16"]).unwrap_err();
    assert!(err.contains("unknown option 'int_bitz'"), "{err}");
    let err = resolved_settings(&["--set", "int_bits=wide"]).unwrap_err();
    assert!(err.contains("int_bits takes a number of bits"), "{err}");
    let err = resolved_settings(&["--set", "char_signed=maybe"]).unwrap_err();
    assert!(err.contains("char_signed takes true or false"), "{err}");
    let err = resolved_settings(&["--data-model", "ilp64"]).unwrap_err();
    assert!(err.contains("ilp64"), "{err}");
}

/// A manifest whose `[environment]` table is `environment`, written to a
/// fresh directory; returns the directory (kept alive) and the path.
fn manifest_with_environment(environment: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("rules.toml");
    std::fs::write(
        &manifest,
        format!(
            "[metadata]\nname = \"t\"\nversion = \"1\"\ncert_version = \"2016\"\n\n\
             [environment]\n{environment}\n\n[rules.cert_c]\n"
        ),
    )
    .unwrap();
    let path = manifest.to_str().unwrap().to_string();
    (dir, path)
}

#[test]
fn check_config_accepts_a_valid_configuration_and_scans_nothing() {
    let (_dir, m) = manifest_with_environment("data_model = \"ilp32\"\nwchar_t_bits = 16\n");
    // The path does not exist: nothing is scanned.
    let (code, stdout, stderr) = run_aurora_lint(&["--check-config", "-m", &m, "/no/such/path"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout.trim(), "configuration ok");
    assert!(stderr.is_empty(), "{stderr}");
}

#[test]
fn check_config_refuses_each_invalid_class_with_its_own_message() {
    for (environment, expected) in [
        ("int_bitz = 16\n", "unknown field `int_bitz`"),
        ("int_bits = \"wide\"\n", "invalid type: string \"wide\""),
        ("data_model = \"ilp64\"\n", "unknown variant `ilp64`"),
        ("int_bits = 8\n", "int_bits = 8 is below the 16 bits"),
        ("long_bits = 16\n", "long_bits = 16 is below the 32 bits"),
        (
            "int_bits = 64\nlong_bits = 32\n",
            "int_bits = 64 is wider than long_bits = 32",
        ),
        ("pointer_bits = 128\n", "up to 64 bits"),
    ] {
        let (_dir, m) = manifest_with_environment(environment);
        let (code, stdout, stderr) = run_aurora_lint(&["--check-config", "-m", &m]);
        assert_ne!(code, 0, "{environment}: {stdout}");
        assert!(stdout.is_empty(), "{environment}: {stdout}");
        assert!(stderr.starts_with("error:"), "{environment}: {stderr}");
        assert!(stderr.contains(expected), "{environment}: {stderr}");
    }
}

#[test]
fn check_config_reports_every_problem_on_a_line_of_its_own() {
    let (_dir, m) = manifest_with_environment("int_bits = 8\nlong_long_bits = 32\n");
    let (code, _stdout, stderr) = run_aurora_lint(&["--check-config", "-m", &m]);
    assert_ne!(code, 0);
    let errors: Vec<&str> = stderr.lines().filter(|l| l.starts_with("error:")).collect();
    assert!(errors.len() >= 2, "{stderr}");
    assert!(
        errors.iter().any(|l| l.contains("int_bits = 8")),
        "{stderr}"
    );
    assert!(
        errors.iter().any(|l| l.contains("long_long_bits = 32")),
        "{stderr}"
    );
}

#[test]
fn check_config_and_a_scan_judge_a_configuration_by_the_same_code() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("a.c");
    std::fs::write(&file, "int main(void) { return 0; }\n").unwrap();
    let f = file.to_str().unwrap();
    // What --check-config refuses, a scan refuses with the same problem and
    // scans nothing; what it accepts, a scan runs.
    let (check_code, _out, check_err) =
        run_aurora_lint(&["--check-config", "--set", "int_bits=8", f]);
    let (scan_code, _out, scan_err) = run_aurora_lint(&["--set", "int_bits=8", f]);
    assert_ne!(check_code, 0);
    assert_ne!(scan_code, 0);
    assert!(
        check_err.contains("int_bits = 8 is below the 16 bits"),
        "{check_err}"
    );
    assert!(
        scan_err.contains("int_bits = 8 is below the 16 bits"),
        "{scan_err}"
    );
    let (ok_code, ok_out, _err) = run_aurora_lint(&["--check-config", "--set", "int_bits=16", f]);
    assert_eq!(ok_code, 0);
    assert_eq!(ok_out.trim(), "configuration ok");
}

#[test]
fn list_options_names_the_source_of_every_integer_fact() {
    // A data model, a project override, and a command-line override of a
    // different fact: each fact carries the layer it came from.
    let (_dir, m) = manifest_with_environment("data_model = \"lp64\"\nint_bits = 16\n");
    let (code, stdout, stderr) = run_aurora_lint(&[
        "--list-options",
        "json",
        "-m",
        &m,
        "--set",
        "long_bits=64",
        "--set",
        "char_signed=true",
    ]);
    assert_eq!(code, 0, "{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let source = |key: &str| -> (String, String) {
        let fact = json["facts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["key"] == key)
            .unwrap_or_else(|| panic!("no fact {key}: {stdout}"));
        (
            fact["value"].as_str().unwrap().to_string(),
            fact["source"].as_str().unwrap().to_string(),
        )
    };
    assert_eq!(
        source("short_bits"),
        ("16".to_string(), "data-model:lp64".to_string())
    );
    assert_eq!(source("int_bits"), ("16".to_string(), "config".to_string()));
    assert_eq!(source("long_bits"), ("64".to_string(), "cli".to_string()));
    assert_eq!(
        source("char_signed"),
        ("true".to_string(), "cli".to_string())
    );
    assert_eq!(
        source("wchar_t_bits"),
        ("unknown".to_string(), "unknown".to_string())
    );
    // Under no data model a width is only the ISO floor.
    let (code, stdout, _err) = run_aurora_lint(&["--list-options", "json"]);
    assert_eq!(code, 0);
    let iso: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let int_bits = iso["facts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["key"] == "int_bits")
        .unwrap();
    assert_eq!(int_bits["value"], ">= 16");
    assert_eq!(int_bits["source"], "iso-floor");
    // The text listing shows the same lines.
    let (_code, text, _err) = run_aurora_lint(&["--list-options", "--data-model", "llp64"]);
    assert!(
        text.lines().any(|l| l.starts_with("wchar_t_bits")
            && l.contains("16")
            && l.contains("data-model:llp64")),
        "{text}"
    );
}

#[test]
fn a_profile_keeps_the_manifests_data_model() {
    // A data model chooses policy, not what the project is built for.
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("rules.toml");
    std::fs::write(
        &manifest,
        "[metadata]\nname = \"t\"\nversion = \"1\"\ncert_version = \"2016\"\n\n[environment]\ndata_model = \"lp64\"\n\n[rules.cert_c]\n",
    )
    .unwrap();
    let m = manifest.to_str().unwrap();
    for profile in ["default", "strict", "pedantic"] {
        let (code, stdout, stderr) =
            run_aurora_lint(&["--list-options", "json", "-m", m, "--profile", profile]);
        assert_eq!(code, 0, "{stderr}");
        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(json["current"]["data_model"], "lp64", "{profile}: {stdout}");
    }
}

/// What `--write-config` writes for `args`, in a fresh directory.
fn written_config(args: &[&str]) -> (tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("aurora.toml");
    let path = file.to_str().unwrap().to_string();
    let mut full = vec!["--write-config", path.as_str()];
    full.extend_from_slice(args);
    let (code, _stdout, stderr) = run_aurora_lint(&full);
    assert_eq!(code, 0, "{stderr}");
    let text = std::fs::read_to_string(&file).unwrap();
    (dir, path, text)
}

#[test]
fn a_written_config_passes_check_config_unchanged() {
    for args in [
        vec![],
        vec!["--data-model", "ilp32"],
        vec![
            "--data-model",
            "lp64",
            "--set",
            "int_bits=32",
            "--set",
            "char_signed=true",
        ],
        vec!["--data-model", "llp64"],
        vec!["--profile", "strict"],
        vec!["--profile", "pedantic"],
        vec!["--profile", "pedantic", "--environment", "hosted"],
    ] {
        let (_dir, path, _text) = written_config(&args);
        let (code, stdout, stderr) = run_aurora_lint(&["--check-config", "-m", &path]);
        assert_eq!(code, 0, "{args:?}: {stderr}");
        assert_eq!(stdout.trim(), "configuration ok");
    }
}

#[test]
fn a_written_config_resolves_to_the_facts_and_hash_of_running_without_it() {
    for model in [
        None,
        Some("iso"),
        Some("ilp32"),
        Some("lp64"),
        Some("llp64"),
    ] {
        let args: Vec<&str> = model.iter().flat_map(|m| ["--data-model", *m]).collect();
        let (_dir, path, _text) = written_config(&args);
        let with_file = vec!["--list-options", "json", "-m", path.as_str()];
        let from_file = run_aurora_lint(&with_file).1;
        let mut direct = vec!["--list-options", "json"];
        direct.extend_from_slice(&args);
        let from_flags = run_aurora_lint(&direct).1;
        // The resolved settings, hash included, and every fact's value agree;
        // a repeated line keeps its true source (config), which is not part
        // of what was resolved.
        let current = |text: &str| {
            serde_json::from_str::<serde_json::Value>(text).unwrap()["current"].clone()
        };
        assert_eq!(current(&from_file), current(&from_flags), "{model:?}");
        assert_eq!(fact_values(&["-m", &path]), fact_values(&args), "{model:?}");
    }
}

#[test]
fn a_written_config_keeps_what_the_command_line_set_as_a_declaration() {
    let (_dir, path, text) = written_config(&["--data-model", "lp64", "--set", "int_bits=64"]);
    assert!(
        text.contains("\nint_bits = 64  # set on the command line\n"),
        "{text}"
    );
    assert!(
        text.contains("\nlong_bits = 64  # from data model: lp64\n"),
        "{text}"
    );
    let from_file = resolved_settings(&["-m", &path]).unwrap();
    let from_flags = resolved_settings(&["--data-model", "lp64", "--set", "int_bits=64"]).unwrap();
    assert_eq!(from_file, from_flags);
    assert_eq!(from_file["int_bits"], 64);
}

#[test]
fn a_written_config_names_every_key_and_comments_out_the_defaults() {
    let (_dir, _path, text) = written_config(&[]);
    for key in [
        "profile",
        "level",
        "kind",
        "libc",
        "include_names",
        "data_model",
        "short_bits",
        "int_bits",
        "long_bits",
        "long_long_bits",
        "pointer_bits",
        "wchar_t_bits",
        "char_signed",
        "closed_program",
        "assert_is_guard",
    ] {
        assert!(text.contains(&format!("# {key} = ")), "{key}: {text}");
    }
    // Facts no data model sets are marked, never given a value of their own.
    assert!(
        text.contains("# char_signed = true  # unknown unless declared"),
        "{text}"
    );
    assert!(text.contains("# wchar_t_bits = "), "{text}");
    // At the defaults nothing outside the metadata and the rules is active.
    let settings = text.split("[metadata]").next().unwrap();
    assert!(
        settings
            .lines()
            .all(|l| l.is_empty() || l.starts_with('#') || l.starts_with('[')),
        "{settings}"
    );
}

#[test]
fn a_data_model_writes_its_bundle_as_active_lines_and_leaves_the_rest_unknown() {
    let (_dir, _path, text) = written_config(&["--data-model", "ilp32"]);
    assert!(text.contains("\ndata_model = \"ilp32\"\n"), "{text}");
    assert!(
        text.contains("\nint_bits = 32  # from data model: ilp32\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "# wchar_t_bits = 16  # unknown unless declared (16 on Windows, 32 on Linux)"
        ),
        "{text}"
    );
    assert!(
        text.contains("# char_signed = true  # unknown unless declared"),
        "{text}"
    );
}

#[test]
fn write_config_refuses_to_overwrite_unless_told_to() {
    let (_dir, path, first) = written_config(&[]);
    std::fs::write(&path, "# mine\n").unwrap();
    let (code, _out, stderr) = run_aurora_lint(&["--write-config", &path]);
    assert_ne!(code, 0);
    assert!(stderr.contains("exists; pass --overwrite"), "{stderr}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "# mine\n");
    let (code, _out, stderr) = run_aurora_lint(&["--write-config", &path, "--overwrite"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
}

#[test]
fn write_config_to_a_dash_prints_the_file_and_nothing_else() {
    let (_dir, _path, file) = written_config(&["--data-model", "lp64"]);
    let (code, stdout, stderr) = run_aurora_lint(&["--write-config", "-", "--data-model", "lp64"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, file);
}

#[test]
fn write_config_refuses_settings_a_scan_would_refuse() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.toml");
    let (code, _out, stderr) = run_aurora_lint(&[
        "--write-config",
        path.to_str().unwrap(),
        "--set",
        "int_bits=8",
    ]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("int_bits = 8 is below the 16 bits"),
        "{stderr}"
    );
    assert!(!path.exists());
}

#[test]
fn an_edited_written_config_is_checked_like_any_other() {
    let (_dir, path, text) = written_config(&["--data-model", "lp64"]);
    let edited = text.replace("int_bits = 32  # from data model: lp64", "int_bits = 8");
    std::fs::write(&path, edited).unwrap();
    let (code, _out, stderr) = run_aurora_lint(&["--check-config", "-m", &path]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("int_bits = 8 is below the 16 bits"),
        "{stderr}"
    );
}

/// The keys a data model loads, as `--list-options` reports them.
fn data_model_keys(model: &str) -> Vec<(String, String)> {
    let (code, stdout, stderr) =
        run_aurora_lint(&["--list-options", "json", "--data-model", model]);
    assert_eq!(code, 0, "{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    json["facts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["source"].as_str().unwrap().starts_with("data-model:"))
        .map(|f| {
            (
                f["key"].as_str().unwrap().to_string(),
                f["value"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

/// The resolved facts of a run, key and value only, whatever their source.
fn fact_values(args: &[&str]) -> Vec<(String, String)> {
    let mut full = vec!["--list-options", "json"];
    full.extend_from_slice(args);
    let (code, stdout, stderr) = run_aurora_lint(&full);
    assert_eq!(code, 0, "{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    json["facts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["key"].as_str().unwrap().to_string(),
                f["value"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

/// Every finding of a scan of the integer rules' fixtures, one per line.
fn fixture_findings(extra: &[&str]) -> Vec<String> {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut findings = Vec::new();
    for rule in ["INT/INT30-C", "INT/INT32-C", "EXP/EXP14-C"] {
        let dir = format!("{root}/src/rules/cert_c/{rule}/tests");
        let mut args = vec![dir.as_str(), "--rules", "INT30-C,INT32-C,EXP14-C"];
        args.extend_from_slice(extra);
        let (_code, stdout, _stderr) = run_aurora_lint(&args);
        findings.extend(
            stdout
                .lines()
                .filter(|l| l.contains("-C: "))
                .map(|l| l.replace(root, "")),
        );
    }
    findings.sort();
    findings
}

#[test]
fn a_data_model_is_exactly_the_keys_a_user_can_write() {
    for model in ["ilp32", "lp64", "llp64"] {
        let keys = data_model_keys(model);
        assert!(keys.len() >= 9, "{model}: {keys:?}");
        let sets: Vec<String> = keys.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let mut by_hand: Vec<&str> = Vec::new();
        for s in &sets {
            by_hand.extend(["--set", s.as_str()]);
        }
        // The same resolved facts as selecting the data model...
        assert_eq!(
            fact_values(&by_hand),
            fact_values(&["--data-model", model]),
            "{model}"
        );
        // ... and so the same findings.
        let hand_written = fixture_findings(&by_hand);
        let selected = fixture_findings(&["--data-model", model]);
        assert!(!selected.is_empty());
        assert_eq!(hand_written, selected, "{model}");
    }
}

#[test]
fn every_fact_is_a_key_a_project_can_write() {
    for key in [
        "char_bits",
        "short_bits",
        "int_bits",
        "long_bits",
        "long_long_bits",
        "pointer_bits",
        "wchar_t_bits",
        "float_bytes",
        "double_bytes",
        "long_double_bytes",
        "time_t_bytes",
        "off_t_bytes",
    ] {
        let value = if key.ends_with("_bytes") { "8" } else { "64" };
        let assignment = format!("{key}={value}");
        let (code, _out, stderr) = run_aurora_lint(&["--check-config", "--set", &assignment]);
        assert_eq!(code, 0, "{key}: {stderr}");
    }
    let (code, _out, stderr) = run_aurora_lint(&["--check-config", "--set", "float_bytes=0"]);
    assert_ne!(code, 0);
    assert!(stderr.contains("a size is from 1 to 64 bytes"), "{stderr}");
}

#[test]
fn a_generated_config_yields_to_a_later_data_model_whole() {
    let (_dir, path, _text) = written_config(&["--data-model", "lp64"]);
    // The command line's model replaces the whole bundle, including the lines
    // the file only repeated from its own model.
    assert_eq!(
        fact_values(&["-m", &path, "--data-model", "ilp32"]),
        fact_values(&["--data-model", "ilp32"])
    );
    let facts = resolved_settings(&["-m", &path, "--data-model", "ilp32"]).unwrap();
    assert_eq!(facts["data_model"], "ilp32");
    assert!(facts["long_bits"].is_null(), "{facts}");
    assert!(facts["pointer_bits"].is_null(), "{facts}");
    // The hash is the model's own, as if the file had not been there.
    assert_eq!(
        facts["hash"],
        resolved_settings(&["--data-model", "ilp32"]).unwrap()["hash"]
    );
}

#[test]
fn a_genuine_override_in_a_file_survives_a_later_data_model() {
    let (_dir, path, text) = written_config(&["--data-model", "lp64"]);
    let edited = text.replace(
        "short_bits = 16  # from data model: lp64",
        "short_bits = 32",
    );
    assert_ne!(edited, text);
    std::fs::write(&path, edited).unwrap();
    for model in ["ilp32", "lp64"] {
        let facts = fact_values(&["-m", &path, "--data-model", model]);
        assert!(
            facts.contains(&("short_bits".to_string(), "32".to_string())),
            "{model}: {facts:?}"
        );
    }
}

#[test]
fn a_key_repeating_the_data_model_hashes_alike_from_the_command_line_and_a_file() {
    let bare = resolved_settings(&["--data-model", "lp64"]).unwrap();
    let by_flag = resolved_settings(&["--data-model", "lp64", "--set", "int_bits=32"]).unwrap();
    let (_dir, m) = manifest_with_environment("data_model = \"lp64\"\nint_bits = 32\n");
    let by_file = resolved_settings(&["-m", &m]).unwrap();
    assert_eq!(bare["hash"], by_flag["hash"]);
    assert_eq!(bare["hash"], by_file["hash"]);
    assert!(by_flag["int_bits"].is_null(), "{by_flag}");
    // ... while the listing still says who wrote the line.
    let source_of = |args: &[&str]| {
        let mut full = vec!["--list-options", "json"];
        full.extend_from_slice(args);
        let json: serde_json::Value = serde_json::from_str(&run_aurora_lint(&full).1).unwrap();
        json["facts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["key"] == "int_bits")
            .unwrap()["source"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(
        source_of(&["--data-model", "lp64", "--set", "int_bits=32"]),
        "cli"
    );
    assert_eq!(source_of(&["-m", &m]), "config");
}

#[test]
fn check_config_names_a_bad_set_and_a_bad_manifest_each_once_and_exits_one() {
    let (_dir, m) = manifest_with_environment("int_bits = 8\n");
    let (code, stdout, stderr) = run_aurora_lint(&[
        "--check-config",
        "-m",
        &m,
        "--set",
        "no_such_option=true",
        "--set",
        "long_bits=wide",
    ]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    let errors: Vec<&str> = stderr.lines().filter(|l| l.starts_with("error:")).collect();
    assert_eq!(errors.len(), 3, "{stderr}");
    assert!(
        errors.iter().any(|l| l.contains("no_such_option")),
        "{stderr}"
    );
    assert!(
        errors
            .iter()
            .any(|l| l.contains("long_bits takes a number")),
        "{stderr}"
    );
    assert!(
        errors.iter().any(|l| l.contains("int_bits = 8 is below")),
        "{stderr}"
    );
}

#[test]
fn check_config_gives_one_message_per_problem() {
    let (code, _out, stderr) = run_aurora_lint(&[
        "--check-config",
        "--set",
        "int_bits=1",
        "--set",
        "char_bits=7",
    ]);
    assert_eq!(code, 1, "{stderr}");
    let errors: Vec<&str> = stderr.lines().filter(|l| l.starts_with("error:")).collect();
    assert_eq!(errors.len(), 2, "{stderr}");
    assert!(
        errors.iter().any(|l| l.contains("char_bits = 7")),
        "{stderr}"
    );
    assert!(
        errors.iter().any(|l| l.contains("int_bits = 1")),
        "{stderr}"
    );
    // An argument the parser itself rejects is a syntax error: exit 2.
    let (code, _out, _stderr) = run_aurora_lint(&["--check-config", "--data-model", "lp128"]);
    assert_eq!(code, 2);
}

/// The messages INT08-C prints for `unsigned char r = p;` in the else branch
/// of `if (p <= UCHAR_MAX)`, one per line of the scanned source, under
/// `model`. The fixture harness checks that a FAIL fixture reports and never
/// what it says, so the wording of an open range end is guarded here.
fn int08_c_messages(model: &str, source: &str) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("scan.c");
    std::fs::write(&file, source).unwrap();
    let out = dir.path().join("out.json");
    let (code, _, stderr) = run_aurora_lint(&[
        "--rules",
        "INT08-C",
        "--data-model",
        model,
        "-e",
        out.to_str().unwrap(),
        file.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    let findings: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    findings
        .iter()
        .map(|v| v["message"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn int08_c_an_unsigned_64_bit_top_prints_as_at_least_never_as_a_bound() {
    // Spelled out and through a typedef: the range engine keeps the top of an
    // unsigned 64-bit type as the i64 limit, which is a clamp and not a bound
    // of the value, and a typedef name tells it nothing at all.
    let shapes = [
        "void f(unsigned long long p) { if (p <= UCHAR_MAX) {} else { unsigned char r = p; } }",
        "typedef unsigned long long u64;\n\
         void f(u64 p) { if (p <= UCHAR_MAX) {} else { unsigned char r = p; } }",
    ];
    for source in shapes {
        for model in ["iso", "lp64", "ilp32", "llp64"] {
            let messages = int08_c_messages(model, &format!("#include <limits.h>\n{source}\n"));
            assert_eq!(messages.len(), 1, "{model}: {source}: {messages:?}");
            assert!(
                messages[0].contains("is at least 256 "),
                "{model}: {source}: {}",
                messages[0]
            );
            assert!(
                !messages[0].contains("9223372036854775807"),
                "{model}: {source}: {}",
                messages[0]
            );
        }
    }
    // A local, not a parameter, with the store in the else of the cap.
    for model in ["iso", "lp64", "ilp32", "llp64"] {
        let source = "#include <limits.h>\n\
             typedef unsigned long long u64;\n\
             void f(void) { u64 d = ULLONG_MAX; if (d <= UCHAR_MAX) {} else { unsigned char r = d; } }\n";
        let messages = int08_c_messages(model, source);
        assert_eq!(messages.len(), 1, "{model}: {messages:?}");
        assert!(
            messages[0].contains("is at least 256 "),
            "{model}: {}",
            messages[0]
        );
        assert!(
            !messages[0].contains("9223372036854775807"),
            "{model}: {}",
            messages[0]
        );
    }
    // Under lp64 `unsigned long` is the same 64 bits, so it reads the same.
    for source in [
        "void f(unsigned long p) { if (p <= UCHAR_MAX) {} else { unsigned char r = p; } }",
        "typedef unsigned long ul_t;\n\
         void f(ul_t p) { if (p <= UCHAR_MAX) {} else { unsigned char r = p; } }",
    ] {
        let messages = int08_c_messages("lp64", &format!("#include <limits.h>\n{source}\n"));
        assert_eq!(messages.len(), 1, "{source}: {messages:?}");
        assert!(messages[0].contains("is at least 256 "), "{}", messages[0]);
        assert!(
            !messages[0].contains("9223372036854775807"),
            "{}",
            messages[0]
        );
    }
}

#[test]
fn int08_c_a_32_bit_unsigned_top_is_the_true_upper_bound() {
    let messages = int08_c_messages(
        "ilp32",
        "#include <limits.h>\n\
         void f(unsigned long p) { if (p <= UCHAR_MAX) {} else { unsigned char r = p; } }\n",
    );
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(
        messages[0].contains("in [256, 4294967295]"),
        "{}",
        messages[0]
    );
}

// ── Graceful failure: crashes and bounds (ADR-0017) ─────────────────────────
//
// `AURORA_LINT_TEST_FAIL` is a debug-build hook (src/analyze/mod.rs): it
// makes a named rule's check panic or spin, so these tests exercise
// containment without a buggy rule to hand. The hook is compiled only under
// `debug_assertions` and stays out of release builds, so every test that
// uses it is ignored under `cargo test --release`.

/// Run aurora-lint with `AURORA_LINT_TEST_FAIL=spec`.
fn run_failing(spec: &str, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(aurora_lint_bin())
        .env("AURORA_LINT_TEST_FAIL", spec)
        .args(args)
        .output()
        .expect("failed to execute aurora-lint");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// A directory holding `n` copies of the MSC04-C violation fixture.
fn copies_of_violation(n: usize) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let src = std::fs::read_to_string(fixtures().join("violation.c")).unwrap();
    for i in 0..n {
        std::fs::write(dir.path().join(format!("v{i}.c")), &src).unwrap();
    }
    dir
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "AURORA_LINT_TEST_FAIL hook is debug-only"
)]
fn a_crashing_rule_exits_three_ahead_of_fail_on_violation() {
    let (code, _, stderr) = run_failing(
        "MSC04-C:panic",
        &[
            fixtures().join("violation.c").to_str().unwrap(),
            "-m",
            manifest_msc04().to_str().unwrap(),
            "--fail-on-violation",
        ],
    );
    assert_eq!(code, 3, "{stderr}");
    assert!(
        stderr.contains("Error: rule failure (crashed): MSC04-C: "),
        "{stderr}"
    );
    assert!(stderr.contains("scan INCOMPLETE"), "{stderr}");
    assert!(
        !stderr.contains("panicked at"),
        "contained panics are quiet: {stderr}"
    );
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "AURORA_LINT_TEST_FAIL hook is debug-only"
)]
fn a_crash_costs_only_that_rule_and_file() {
    // MSC04-C crashes; DCL31-C on the same file still reports.
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("m.toml");
    std::fs::write(
        &manifest,
        "[metadata]\nname = \"t\"\nversion = \"1\"\ncert_version = \"2016\"\n\n\
         [rules.cert_c.MSC04-C]\nenabled = true\n\n[rules.cert_c.DCL31-C]\nenabled = true\n",
    )
    .unwrap();
    let src = dir.path().join("a.c");
    std::fs::write(&src, "void f(void) { g(); }\n").unwrap();
    let (code, stdout, stderr) = run_failing(
        "MSC04-C:panic",
        &[src.to_str().unwrap(), "-m", manifest.to_str().unwrap()],
    );
    assert_eq!(code, 3, "{stderr}");
    assert!(stdout.contains("DCL31-C"), "{stdout}");
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "AURORA_LINT_TEST_FAIL hook is debug-only"
)]
fn a_runaway_rule_stops_at_its_step_limit() {
    let (code, _, stderr) = run_failing(
        "MSC04-C:spin",
        &[
            fixtures().join("violation.c").to_str().unwrap(),
            "-m",
            manifest_msc04().to_str().unwrap(),
            "--rule-step-limit",
            "1000",
        ],
    );
    assert_eq!(code, 3, "{stderr}");
    assert!(
        stderr.contains("rule failure (step limit): MSC04-C: ")
            && stderr.contains("stopped after 1000 steps"),
        "{stderr}"
    );
    assert!(
        stderr.contains("--rule-step-limit / --rule-time-limit"),
        "{stderr}"
    );
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "AURORA_LINT_TEST_FAIL hook is debug-only"
)]
fn a_rule_failing_on_three_files_is_abandoned_and_withheld() {
    let dir = copies_of_violation(4);
    for jobs in ["1", "4"] {
        let (code, stdout, stderr) = run_failing(
            "MSC04-C:panic",
            &[
                dir.path().to_str().unwrap(),
                "-m",
                manifest_msc04().to_str().unwrap(),
                "-j",
                jobs,
            ],
        );
        assert_eq!(code, 3, "{stderr}");
        assert!(
            stderr.contains("Error: rule abandoned: MSC04-C: failed on 3 or more files"),
            "jobs {jobs}: {stderr}"
        );
        assert!(!stdout.contains("MSC04-C:"), "jobs {jobs}: {stdout}");
    }
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "AURORA_LINT_TEST_FAIL hook is debug-only"
)]
fn two_failures_do_not_abandon_a_rule() {
    let dir = copies_of_violation(2);
    let (code, _, stderr) = run_failing(
        "MSC04-C:panic",
        &[
            dir.path().to_str().unwrap(),
            "-m",
            manifest_msc04().to_str().unwrap(),
        ],
    );
    assert_eq!(code, 3, "{stderr}");
    assert!(!stderr.contains("rule abandoned"), "{stderr}");
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "AURORA_LINT_TEST_FAIL hook is debug-only"
)]
fn sarif_records_an_incomplete_scan() {
    let dir = tempfile::tempdir().unwrap();
    let sarif = dir.path().join("out.sarif");
    let (code, _, stderr) = run_failing(
        "MSC04-C:panic",
        &[
            fixtures().join("violation.c").to_str().unwrap(),
            "-m",
            manifest_msc04().to_str().unwrap(),
            "-e",
            sarif.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 3, "{stderr}");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sarif).unwrap()).unwrap();
    let inv = &doc["runs"][0]["invocations"][0];
    assert_eq!(inv["executionSuccessful"], false);
    let n = &inv["toolExecutionNotifications"][0];
    assert_eq!(n["level"], "error");
    assert_eq!(n["associatedRule"]["id"], "MSC04-C");
    assert_eq!(n["descriptor"]["id"], "aurora-lint/incomplete/rule");
    assert_eq!(n["properties"]["cause"], "crash");
}

#[test]
fn sarif_records_a_complete_scan() {
    let dir = tempfile::tempdir().unwrap();
    let sarif = dir.path().join("out.sarif");
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "-e",
        sarif.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sarif).unwrap()).unwrap();
    let inv = &doc["runs"][0]["invocations"][0];
    assert_eq!(inv["executionSuccessful"], true);
    assert_eq!(inv["toolExecutionNotifications"], serde_json::json!([]));
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "AURORA_LINT_TEST_FAIL hook is debug-only"
)]
fn an_incomplete_prescan_is_reported_and_not_cached() {
    let dir = copies_of_violation(2);
    let cache = dir.path().join("ctx.prescan");
    let (code, _, stderr) = run_failing(
        "prescan:panic",
        &[
            dir.path().to_str().unwrap(),
            "-m",
            manifest_msc04().to_str().unwrap(),
            "-d",
            dir.path().to_str().unwrap(),
            "--save-prescan",
            cache.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 3, "{stderr}");
    assert!(stderr.contains("prescan failure (crashed): "), "{stderr}");
    assert!(stderr.contains("not saving the prescan cache"), "{stderr}");
    assert!(!cache.exists());
}

// ── Input guard: non-source and oversized files (ADR-0017) ─────────────────

/// The first 64 bytes of a 64-bit ELF file: enough for a magic-number match.
fn elf_header() -> Vec<u8> {
    let mut h = b"\x7fELF\x02\x01\x01".to_vec();
    h.resize(64, 0);
    h
}

#[test]
fn a_binary_named_dot_c_is_skipped_and_reported() {
    let dir = copies_of_violation(1);
    std::fs::write(dir.path().join("blob.c"), elf_header()).unwrap();
    let mut nuls = b"int x;".to_vec();
    nuls.extend_from_slice(&[0u8; 32]);
    std::fs::write(dir.path().join("nul.c"), nuls).unwrap();
    let (code, stdout, stderr) = run_aurora_lint(&[
        dir.path().to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
    ]);
    assert_eq!(code, 3, "{stderr}");
    assert!(
        stderr.contains("input skipped (not source text): ")
            && stderr.contains("blob.c: looks like binary data (Elf"),
        "{stderr}"
    );
    assert!(stderr.contains("nul.c: looks like binary data"), "{stderr}");
    assert!(stderr.contains("--exclude-all"), "{stderr}");
    // The real source in the same scan is still analysed.
    assert!(stdout.contains("MSC04-C"), "{stdout}");
}

#[test]
fn a_file_over_the_size_ceiling_is_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big.c");
    let mut src = String::from("void infinite(void) {\n    infinite();\n}\n");
    while src.len() < 2 * 1024 * 1024 {
        src.push_str("/* padding padding padding padding padding padding padding */\n");
    }
    std::fs::write(&big, &src).unwrap();
    let (code, _, stderr) = run_aurora_lint(&[
        big.to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "--max-file-size",
        "1",
    ]);
    assert_eq!(code, 3, "{stderr}");
    assert!(
        stderr.contains("input skipped (too large): ")
            && stderr.contains("is over --max-file-size 1 MiB"),
        "{stderr}"
    );
    // (Admission under the default ceiling is what every other test here
    // exercises; scanning this padded file in a debug build is slow.)
}

#[test]
fn utf16_source_with_a_bom_is_not_mistaken_for_binary() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wide.c");
    let src = std::fs::read_to_string(fixtures().join("violation.c")).unwrap();
    let mut bytes = vec![0xFF, 0xFE];
    for unit in src.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    std::fs::write(&path, bytes).unwrap();
    let (code, stdout, stderr) = run_aurora_lint(&[
        path.to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("MSC04-C"), "{stdout}");
}

#[test]
fn an_excluded_binary_is_not_reported() {
    let dir = copies_of_violation(1);
    std::fs::write(dir.path().join("blob.c"), elf_header()).unwrap();
    let (code, _, stderr) = run_aurora_lint(&[
        dir.path().to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "--exclude-all",
        "blob.c",
    ]);
    assert_eq!(code, 0, "{stderr}");
    assert!(!stderr.contains("input skipped"), "{stderr}");
}

/// A file's analysis time grows with its length, not its square, when most of
/// it is comments. Every comment is a child of the translation unit, and
/// tree-sitter answers `Node::child(i)` by walking from the first child, so a
/// pass that indexes the root's children one by one is quadratic in them. An
/// 8x longer file must cost about 8x, not about 64x: the ratio is checked
/// rather than a time, so a slow or loaded machine does not fail it.
#[test]
fn comment_padding_costs_linear_time() {
    let dir = tempfile::tempdir().unwrap();
    let padded = |kib: usize| {
        let head = "int f(int x)\n{\n    return x + 1;\n}\n";
        let line = "/* padding padding padding padding padding padding padding */\n";
        let path = dir.path().join(format!("pad{kib}.c"));
        std::fs::write(
            &path,
            head.to_string() + &line.repeat((kib * 1024 - head.len()) / line.len()),
        )
        .unwrap();
        path
    };
    let (small, large) = (padded(32), padded(256));
    let report = dir.path().join("report.json");
    let time = |path: &PathBuf| {
        let started = std::time::Instant::now();
        let (code, _, stderr) = run_aurora_lint(&[
            path.to_str().unwrap(),
            "--jobs",
            "1",
            "--export",
            report.to_str().unwrap(),
        ]);
        assert!(code == 0 || code == 1, "exit {code}: {stderr}");
        started.elapsed().as_secs_f64()
    };
    // The faster of two runs, so one fast outlier cannot inflate the ratio.
    let small_secs = time(&small).min(time(&small));
    let large_secs = time(&large);
    let ratio = large_secs / small_secs;
    assert!(
        ratio < 20.0,
        "8x the comment padding took {ratio:.1}x the time ({small_secs:.2} s -> {large_secs:.2} s)"
    );
}

fn manifest_int30() -> PathBuf {
    fixtures().join("manifest_int30.toml")
}

#[test]
fn crossfile_header_array_plus_integer_is_not_an_unsigned_sum() {
    // `cmd` is declared `extern char cmd[64]` in globals.h only. `cmd + scanned`
    // is pointer arithmetic, so INT30-C must not report it; the integer
    // `total`, a local that shadows the array's name, and a name declared as
    // an array in one file and an integer in another are all still sums.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("crossfile_int30_array");
    let (code, _, _) = run_aurora_lint(&[
        fixture_dir.join("parser.c").to_str().unwrap(),
        "-m",
        manifest_int30().to_str().unwrap(),
        "-d",
        fixture_dir.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let lines: Vec<u64> = violations
        .iter()
        .filter(|v| v["rule_id"] == "INT30-C")
        .filter_map(|v| v["line"].as_u64())
        .collect();

    assert!(
        !lines.contains(&7),
        "cmd + scanned adds to a header-declared array: {lines:?}"
    );
    assert!(
        lines.contains(&13),
        "total + n is an unsigned sum: {lines:?}"
    );
    assert!(
        lines.contains(&19),
        "the local `cmd` is an unsigned int: {lines:?}"
    );
    assert!(
        lines.contains(&25),
        "`shared` is not known to be an array: {lines:?}"
    );
    assert!(
        !lines.contains(&34),
        "s->sme.assoc_req_ie is an array member of an anonymous struct: {lines:?}"
    );
    assert!(
        lines.contains(&40),
        "an integer member of the anonymous struct is still a sum: {lines:?}"
    );
}

#[test]
fn crossfile_struct_redefined_without_the_anonymous_member_keeps_its_own_sum() {
    // a.c's `struct S` has an anonymous `sme` with an array `ie`; b.c defines
    // the same tag with a named-type `sme` whose `ie` is a size_t. Scanning
    // b.c, its own definition wins: the other file's anonymous `sme` must not
    // turn `s->sme.ie + n` into pointer arithmetic.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("crossfile_int30_shape_conflict");
    let (code, _, _) = run_aurora_lint(&[
        fixture_dir.join("b.c").to_str().unwrap(),
        "-m",
        manifest_int30().to_str().unwrap(),
        "-d",
        fixture_dir.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let lines: Vec<u64> = violations
        .iter()
        .filter(|v| v["rule_id"] == "INT30-C")
        .filter_map(|v| v["line"].as_u64())
        .collect();
    assert!(
        lines.contains(&16),
        "s->sme.ie is a size_t here, so the sum is still reported: {lines:?}"
    );
}

#[test]
fn crossfile_wrapper_macro_declared_array_plus_integer_is_not_an_unsigned_sum() {
    // globals.h declares `cmd` only as `GLOBAL0(char cmd[N]);` with
    // `#define GLOBAL0(A) extern A` (and `A` under DEFINE_GLOBALS), and
    // defining.h declares `wd` through a macro whose body is the parameter.
    // Neither is a declaration to the parser, but each expands to one, so
    // `cmd + n` and `wd + n` are pointer arithmetic. A macro-declared integer,
    // an invocation that never closes and a macro that is no wrapper declare
    // nothing an array, so their sums are still reported.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("crossfile_int30_macro_declared");
    let (code, _, _) = run_aurora_lint(&[
        fixture_dir.join("parser.c").to_str().unwrap(),
        "-m",
        manifest_int30().to_str().unwrap(),
        "-d",
        fixture_dir.to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let violations: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let lines: Vec<u64> = violations
        .iter()
        .filter(|v| v["rule_id"] == "INT30-C")
        .filter_map(|v| v["line"].as_u64())
        .collect();
    assert!(
        !lines.contains(&12),
        "cmd is an array declared through GLOBAL0: {lines:?}"
    );
    assert!(lines.contains(&18), "total is an integer: {lines:?}");
    assert!(
        !lines.contains(&24),
        "wd is an array declared through DEFINE: {lines:?}"
    );
    assert!(
        lines.contains(&30),
        "a malformed invocation declares nothing: {lines:?}"
    );
    assert!(
        lines.contains(&36),
        "a macro that is no wrapper declares nothing: {lines:?}"
    );
    assert!(
        lines.contains(&42),
        "arms that disagree do not make `both` an array: {lines:?}"
    );
    assert!(
        !lines.contains(&48),
        "label follows non-ASCII text and is an array: {lines:?}"
    );
}
