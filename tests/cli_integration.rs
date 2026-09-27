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
fn sarif_records_strict_preset_from_cli() {
    let s = sarif_settings(&manifest_msc04(), &["--profile", "strict"]);
    assert_eq!(s["preset"], "strict");
    assert_eq!(s["environment"], "freestanding");
    assert_eq!(s["libc"], serde_json::Value::Null);
    assert_eq!(s["options"]["assert_is_guard"], false);
    assert_eq!(s["options"]["free_null_is_noop"], false);
    assert_eq!(s["options"]["main_argv_guarantees"], false);
}

#[test]
fn manifest_settings_apply_and_name_no_preset_when_overridden() {
    let manifest = fixtures().join("manifest_msc04_strict_newlib.toml");
    let s = sarif_settings(&manifest, &[]);
    // Strict policy, but newlib's documented contracts are trusted and one
    // startup guarantee is withdrawn: neither preset.
    assert_eq!(s["preset"], serde_json::Value::Null);
    assert_eq!(s["policy"], "strict");
    assert_eq!(s["libc"], "newlib");
    assert_eq!(s["options"]["free_null_is_noop"], true);
    assert_eq!(s["options"]["main_argv_guarantees"], false);
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
fn list_options_json_names_every_option_under_both_presets() {
    let (code, stdout, _) = run_aurora_lint(&["--list-options", "json"]);
    assert_eq!(code, 0);
    let listing: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let options = listing["options"].as_array().unwrap();
    assert!(!options.is_empty());
    for o in options {
        assert!(o["default"].is_boolean() && o["strict"].is_boolean(), "{o}");
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

/// A free credited on the deallocator's name alone marks every finding that
/// rests on it `requires_manual_review` -- a double free where either free is
/// the guess, and a use reached through a copy of a copy -- while the same
/// shapes over plain `free` stay unmarked. The generated fixture test only
/// sees whether MEM30-C fires, so the mark is asserted here, per line, from
/// the fixture's own MARKED / UNMARKED tags.
#[test]
fn guessed_free_mark_reaches_double_free_and_copies() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "src/rules/cert_c/MEM/MEM30-C/tests/fail/\
         guessed_free_mark_survives_double_free_and_copies.c",
    );

    let (code, _, _) = run_aurora_lint(&[
        fixture.to_str().unwrap(),
        "-m",
        manifest_mem30().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let violations: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let source = std::fs::read_to_string(&fixture).unwrap();
    let mut tagged = 0;
    for (idx, text) in source.lines().enumerate() {
        let want = if text.contains("VIOLATION MARKED") {
            true
        } else if text.contains("VIOLATION UNMARKED") {
            false
        } else {
            continue;
        };
        tagged += 1;
        let line = idx as u64 + 1;
        let here: Vec<_> = violations
            .iter()
            .filter(|v| v["line"].as_u64() == Some(line))
            .collect();
        assert!(!here.is_empty(), "line {line}: no MEM30-C finding");
        for v in here {
            assert_eq!(
                v["requires_manual_review"].as_bool(),
                Some(want),
                "line {line}: {}",
                v["message"]
            );
        }
    }
    assert_eq!(tagged, 7, "fixture tags changed; update this count");
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
