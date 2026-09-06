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
fn export_csv_has_header_and_row() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.csv");
    let (code, _, _) = run_aurora_lint(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "-e",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&out).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert!(lines.len() >= 2, "CSV should have header + at least 1 row");
    assert!(lines[0].contains("Title"));
    assert!(lines[1].contains("MSC04-C"));
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

    let results = &sarif["runs"][0]["results"];
    assert_eq!(results.as_array().unwrap().len(), 1);
    assert_eq!(results[0]["ruleId"], "MSC04-C");
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

/// Regression (task 185, Phase 2c-i): a function-like macro invocation
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
/// consume it. This is the curl CF_DATA_SAVE FP class (task 185, Phase 2c-ii).
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
/// cleared. Task 185, Phase 2c-iii.
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

// ─── Cross-file frees_params (MEM31-C) ──────────────────────────────────────

fn manifest_mem31() -> PathBuf {
    fixtures().join("manifest_mem31.toml")
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

#[test]
fn arr30_unvalidated_index_suppressed_by_crossfile_caller() {
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
        findings.is_empty(),
        "decode_inject range-checks index before the call; with -d the \
         project-wide summary should reach across the file boundary (got: {:?})",
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

/// The cross-file half of ARR36-C's parameter model (task 936).
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
