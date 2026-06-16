//! CLI integration tests for sqc.
//!
//! These tests invoke the sqc binary as a subprocess and verify:
//! - Export formats (JSON, CSV, SARIF)
//! - Exit codes (--fail-on-violation, --fail-on-severity)
//! - Filtering (--rules, --min-severity)
//! - Prescan caching (--save-prescan, --load-prescan)
//! - Suppression (inline comments and TOML file)
//! - Cross-file analysis (-d flag)
//! - Diff-only mode (--diff flag)

use std::path::PathBuf;
use std::process::Command;

fn sqc_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sqc"))
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

/// Run sqc with given args, return (exit_code, stdout, stderr).
fn run_sqc(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(sqc_bin())
        .args(args)
        .output()
        .expect("failed to execute sqc");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

// ─── Export formats ──────────────────────────────────────────────────────────

#[test]
fn export_json_structure() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
        fixtures().join("clean.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
}

#[test]
fn exit_code_zero_without_fail_flag() {
    let (code, _, _) = run_sqc(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
    ]);
    // Without --fail-on-violation, violations don't cause exit 1
    assert_eq!(code, 0);
}

#[test]
fn fail_on_violation_exits_one() {
    let (code, _, _) = run_sqc(&[
        fixtures().join("violation.c").to_str().unwrap(),
        "-m",
        manifest_msc04().to_str().unwrap(),
        "--fail-on-violation",
    ]);
    assert_eq!(code, 1);
}

#[test]
fn fail_on_violation_exits_zero_when_clean() {
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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

    let (code, _, _) = run_sqc(&[
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

// ─── Suppression ─────────────────────────────────────────────────────────────

#[test]
fn inline_suppression_hides_violation() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, stdout, _) = run_sqc(&[
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

#[test]
fn toml_suppression_hides_violation() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, stdout, _) = run_sqc(&[
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

#[test]
fn fail_on_violation_ignores_suppressed() {
    // Suppressed violations should NOT trigger exit code 1
    let (code, _, _) = run_sqc(&[
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
    let (code, stdout, _) = run_sqc(&[
        "--generate-suppression",
        &format!(
            "{}:1:MSC04-C",
            fixtures().join("violation.c").to_str().unwrap()
        ),
        "-m",
        manifest_msc04().to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("SQC-SUPPRESS: MSC04-C"));
    assert!(stdout.contains("HASH:745a35718a0e2d31"));
    assert!(stdout.contains("[[suppression]]"));
}

// ─── Cross-file analysis (-d) ────────────────────────────────────────────────

#[test]
fn without_d_flag_reports_undeclared_function() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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

    // Init git repo
    Command::new("git")
        .args(["init"])
        .current_dir(repo_dir)
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(repo_dir)
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(repo_dir)
        .output()
        .unwrap();

    // Create and commit a clean file
    let clean = repo_dir.join("clean.c");
    std::fs::write(&clean, "int add(int a, int b) { return a + b; }\n").unwrap();
    Command::new("git")
        .args(["add", "clean.c"])
        .current_dir(repo_dir)
        .output()
        .unwrap();
    Command::new("git")
        .args(["commit", "-m", "initial"])
        .current_dir(repo_dir)
        .output()
        .unwrap();

    // Add an untracked file with a violation
    let violation = repo_dir.join("violation.c");
    std::fs::write(&violation, "void infinite(void) {\n    infinite();\n}\n").unwrap();

    // Copy manifest into the repo
    let manifest = repo_dir.join("manifest.toml");
    std::fs::copy(manifest_msc04(), &manifest).unwrap();

    let out = repo_dir.join("out.json");

    // --diff should only analyze the new/modified file
    // Must run from within the repo so sqc detects the git context correctly
    let output = Command::new(sqc_bin())
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
        .expect("failed to execute sqc");

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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    // Without -d, sqc can't know that cleanup_buffer frees param → MEM31-C flags leak.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("crossfile_frees");
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    let (code, _, _) = run_sqc(&[
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
    // sqc auto-scans sibling .h files even without -d, so public API functions
    // declared in public_api.h should NOT be flagged by DCL15-C.
    // Only internal_helper() — which has no header prototype — should be flagged.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    let fixture_dir = fixtures().join("crossfile_header");
    let (code, _, _) = run_sqc(&[
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
