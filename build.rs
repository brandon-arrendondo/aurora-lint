use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use walkdir::WalkDir;

// The `[presets]` schema and its validation; also compiled into the library
// for its unit tests (src/lib.rs).
#[allow(dead_code)]
#[path = "build/presets.rs"]
mod presets;

#[derive(Deserialize)]
struct RuleConfig {
    rules: Option<HashMap<String, HashMap<String, RuleSettings>>>,
    rule: Option<RuleSingleSettings>,
}

#[derive(Deserialize)]
struct RuleSettings {
    enabled: bool,
}

#[derive(Deserialize)]
struct RuleSingleSettings {
    enabled: bool,
}

// ---------------------------------------------------------------------------
// Build-time manifest validation (see `validate_rule_manifest`).
//
// These structs deliberately mirror the runtime schema in
// `src/manifest/mod.rs` (`RuleNamespaces` / `RuleConfig` / `Severity`) so
// that a syntax error, an unknown/typo'd field, or an invalid enum value in
// an individual rule TOML is caught when `build.rs`
// merges the manifests instead of only when the manifest is loaded at runtime.
// `deny_unknown_fields` is what turns a misspelled key (e.g. `enabld`) into a
// hard build failure. build.rs cannot depend on the crate it is building, so
// the schema is duplicated here; keep it in sync with `src/manifest/mod.rs`.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatedRulesTable {
    #[serde(default)]
    cert_c: HashMap<String, ValidatedRuleConfig>,
    #[serde(default)]
    brules: HashMap<String, ValidatedRuleConfig>,
    #[serde(default)]
    cwe: HashMap<String, ValidatedRuleConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // fields exist only to enforce the schema during deserialize
struct ValidatedRuleConfig {
    enabled: bool,
    severity: Option<ValidatedSeverity>,
    description: Option<String>,
}

#[derive(Deserialize)]
enum ValidatedSeverity {
    Low,
    Medium,
    High,
    Critical,
}

fn main() {
    // Every other rerun-if-changed below narrows Cargo's default "rerun if
    // any package file changed" to just those paths -- which silently stops
    // covering build.rs's OWN source. A generator-logic change here (e.g.
    // an earlier commit reordering the generated tests' own
    // prescan/parse sequence) then never regenerates output on a clone with
    // a pre-existing target/, since none of the narrower paths moved. Watch
    // build.rs itself first so its own edits always trigger a rerun.
    println!("cargo:rerun-if-changed=build.rs");

    // The commit a benchmark container build is building (bench/container.py
    // passes the host's HEAD), embedded in --version so the run can check,
    // before it scans, that the binary in a reused target directory was
    // built from this commit and not from another checkout's. Watching the
    // variable also makes a build for a different commit recompile, whatever
    // the source mtimes say. Unset, --version is the bare package version.
    println!("cargo:rerun-if-env-changed=AURORA_LINT_BUILD_COMMIT");
    let mut version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    if let Ok(commit) = std::env::var("AURORA_LINT_BUILD_COMMIT") {
        if !commit.is_empty() {
            version = format!("{version} (commit {commit})");
        }
    }
    println!("cargo:rustc-env=AURORA_LINT_VERSION={version}");

    // Only compile resources on Windows
    #[cfg(target_os = "windows")]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        if let Err(e) = res.compile() {
            eprintln!("Warning: Failed to compile Windows resources: {}", e);
        }
    }

    // Generate rules-all.toml from individual RULE-ID.toml files
    if let Err(e) = generate_rules_all_toml() {
        eprintln!("Error generating rules-all.toml: {}", e);
        std::process::exit(1);
    }

    // Keep the distributed rules_templates/ manifests (the CLI's embedded
    // built-in default, and the real-world benchmark's manifest) in sync
    // with src/rules/{cert_c,cwe}/rules-all.toml. Without this, newly added rules
    // silently never run for end users or in the real-world benchmark even
    // though they build and pass their own tests -- this exact drift went
    // unnoticed from v0.3.51 through v0.4.139 (26 rules missing).
    if let Err(e) = sync_rules_templates() {
        eprintln!("Error syncing rules_templates manifests: {}", e);
        std::process::exit(1);
    }

    // Validate every rule's [presets] block and generate the table bench reads.
    if let Err(e) = generate_rule_presets() {
        eprintln!("Error in the per-rule preset table: {:#}", e);
        std::process::exit(1);
    }

    // Generate integration tests from C test files
    if let Err(e) = generate_integration_tests() {
        eprintln!("Error generating integration tests: {:#}", e);
        std::process::exit(1);
    }
}

/// The names in `settings::OPTIONS` (src/settings/mod.rs). build.rs cannot
/// link the crate it builds, so it reads the table's `name:` lines: those
/// between `pub static OPTIONS` and `pub static DECLINED_RULES`.
fn settings_option_names() -> Result<std::collections::BTreeSet<String>> {
    let src = fs::read_to_string("src/settings/mod.rs").context("read src/settings/mod.rs")?;
    let start = src
        .find("pub static OPTIONS")
        .context("src/settings/mod.rs has no `pub static OPTIONS`")?;
    let end = src[start..]
        .find("pub static DECLINED_RULES")
        .map(|i| start + i)
        .context("src/settings/mod.rs has no `pub static DECLINED_RULES` after OPTIONS")?;
    let names: std::collections::BTreeSet<String> = src[start..end]
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let name = l.strip_prefix("name: \"")?.strip_suffix("\",")?;
            Some(name.to_string())
        })
        .collect();
    anyhow::ensure!(
        !names.is_empty(),
        "found no option names in settings::OPTIONS"
    );
    Ok(names)
}

/// Read every cert_c rule's `[presets]` block, fail the build on anything
/// `presets::problems` reports, and write `rules_templates/rule-presets.json`
/// (the table bench reads for abstention scoring). Bench stays free of Rust
/// and of the crate: it reads this file.
fn generate_rule_presets() -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut files: Vec<PathBuf> = WalkDir::new("src/rules/cert_c")
        .into_iter()
        .filter_map(|e| e.ok())
        .map(|e| e.into_path())
        .filter(|p| {
            p.extension().is_some_and(|x| x == "toml")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n != "rules-all.toml" && n.contains('-'))
        })
        .collect();
    files.sort();
    let mut rules = BTreeSet::new();
    let mut enabled = BTreeMap::new();
    let mut blocks = BTreeMap::new();
    for path in &files {
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .context("rule file name")?
            .to_string();
        let content = fs::read_to_string(path)?;
        enabled.insert(id.clone(), check_if_rule_enabled(&path.to_string_lossy())?);
        let block = presets::parse(&content)
            .with_context(|| format!("invalid [presets] block in {}", path.display()))?;
        rules.insert(id.clone());
        blocks.insert(id, block);
    }
    let options = settings_option_names()?;
    let ctx = presets::Context {
        rules: &rules,
        options: &options,
        enabled: &enabled,
    };
    let mut problems = Vec::new();
    for (id, block) in &blocks {
        problems.extend(presets::problems(id, block.as_ref(), &ctx));
    }
    anyhow::ensure!(
        problems.is_empty(),
        "the per-rule preset table has {} problem(s):\n  {}",
        problems.len(),
        problems.join("\n  ")
    );
    let table: BTreeMap<String, presets::Block> = blocks
        .into_iter()
        .filter_map(|(id, b)| b.map(|b| (id, b)))
        .collect();
    let json = presets::to_json(&table);
    let out = PathBuf::from("rules_templates/rule-presets.json");
    // Rewrite only on change so an unrelated build does not touch the file.
    if fs::read_to_string(&out).ok().as_deref() != Some(json.as_str()) {
        fs::write(&out, json).context("write rules_templates/rule-presets.json")?;
    }
    let rst = presets::to_rst(&table);
    let page = PathBuf::from("docs/rule-presets.rst");
    if fs::read_to_string(&page).ok().as_deref() != Some(rst.as_str()) {
        fs::write(&page, rst).context("write docs/rule-presets.rst")?;
    }
    println!("cargo:rerun-if-changed=src/settings/mod.rs");
    check_fixture_matrix(&table)
}

/// The fixtures must agree with the table. A fixture of a rule whose presets
/// read it the same way (`differs = false`) may not expect a different verdict
/// under default and strict, and no fixture may name a preset that declines
/// the rule. A rule whose presets do differ should have a fixture whose
/// `Expect:` header says how; those without one are counted in a build
/// warning, not failed, since a rule with no fixtures is allowed
/// (CLAUDE.md) and the differing readings arrive rule by rule.
fn check_fixture_matrix(table: &std::collections::BTreeMap<String, presets::Block>) -> Result<()> {
    let mut problems = Vec::new();
    let mut unexercised = Vec::new();
    for (rule, block) in table {
        // The ruling has moved ahead of the code; the rewrite brings the
        // fixtures along.
        if block.code_lags.is_some() {
            continue;
        }
        let Some(dir) = WalkDir::new("src/rules/cert_c")
            .into_iter()
            .filter_map(|e| e.ok())
            .find(|e| e.file_type().is_dir() && e.file_name().to_str() == Some(rule.as_str()))
            .map(|e| e.into_path().join("tests"))
        else {
            continue;
        };
        let mut any_fixture = false;
        let mut any_expect = false;
        for kind in ["fail", "pass", "expected_fail"] {
            let Ok(entries) = fs::read_dir(dir.join(kind)) else {
                continue;
            };
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.extension().is_none_or(|x| x != "c") {
                    continue;
                }
                any_fixture = true;
                let header = fixture_header(&path)?;
                any_expect |= !header.expect.is_empty();
                let baseline = if kind == "pass" { "clean" } else { "violation" };
                let verdict = |preset: &str| {
                    header
                        .expect
                        .iter()
                        .find(|(p, _)| p == preset)
                        .map_or(baseline, |(_, e)| e.as_str())
                        .to_ascii_lowercase()
                };
                if !block.derived_differs() && verdict("default") != verdict("strict") {
                    problems.push(format!(
                        "{}: expects {} under default and {} under strict, but the table reads {rule} the same under every preset",
                        path.display(),
                        verdict("default"),
                        verdict("strict")
                    ));
                }
                for (preset, _) in &header.expect {
                    let cell = match preset.as_str() {
                        "default" => block.default,
                        "strict" => block.strict,
                        _ => block.pedantic,
                    };
                    if cell == presets::Cell::NotEnforced
                        && block.cells() != [presets::Cell::NotEnforced; 3]
                    {
                        problems.push(format!(
                            "{}: names {preset}, which declines {rule}",
                            path.display()
                        ));
                    }
                }
            }
        }
        if block.derived_differs() && any_fixture && !any_expect {
            unexercised.push(rule.as_str());
        }
    }
    anyhow::ensure!(
        problems.is_empty(),
        "fixtures disagree with the per-rule preset table:\n  {}",
        problems.join("\n  ")
    );
    // A count and a pointer, not the list: this build script reruns often.
    if !unexercised.is_empty() {
        println!(
            "cargo:warning={} rule(s) read differently by some preset have fixtures but none with an `Expect:` header (see `scripts/list_unexercised_presets.py`)",
            unexercised.len()
        );
    }
    Ok(())
}

/// Validate a single individual rule manifest (`<RULE-ID>.toml`) before its
/// `[rules.*]` section is merged into the generated `rules-all.toml`.
///
/// Catches at build time what would otherwise only surface at runtime:
/// 1. TOML syntax errors anywhere in the file;
/// 2. a missing `[rules.<namespace>.<RULE-ID>]` section;
/// 3. unknown / malformed fields and invalid enum values in that section
///    (via `deny_unknown_fields` + the typed `Validated*` schema);
/// 4. a section count other than one, or a rule id that does not match the
///    file name (a common copy-paste error).
fn validate_rule_manifest(path: &std::path::Path, content: &str) -> Result<()> {
    // 1. Whole-file TOML syntax.
    let value: toml::Value = toml::from_str(content)
        .with_context(|| format!("Invalid TOML syntax in rule manifest {}", path.display()))?;

    // 2. A [rules] table must exist.
    let rules = value.get("rules").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule manifest {} has no [rules.<namespace>.<RULE-ID>] section",
            path.display()
        )
    })?;

    // 3. Strict schema for the [rules] table.
    let table: ValidatedRulesTable = rules.clone().try_into().with_context(|| {
        format!(
            "Invalid [rules] schema in {} (unknown/malformed field or bad severity value)",
            path.display()
        )
    })?;

    // 4. Exactly one rule, whose id matches the file name stem.
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid manifest file name: {}", path.display()))?;
    let ids: Vec<&String> = table
        .cert_c
        .keys()
        .chain(table.brules.keys())
        .chain(table.cwe.keys())
        .collect();
    match ids.as_slice() {
        [id] if **id == *stem => Ok(()),
        [id] => anyhow::bail!(
            "Rule id '{}' in {} does not match its file name stem '{}'",
            id,
            path.display(),
            stem
        ),
        _ => anyhow::bail!(
            "Rule manifest {} must declare exactly one rule, found {}: {:?}",
            path.display(),
            ids.len(),
            ids
        ),
    }
}

/// Validate the generated combined `rules-all.toml` for a ruleset. Catches
/// merge-level problems the per-file checks cannot — most importantly a
/// duplicate rule id across two files (TOML forbids redefining a table) and any
/// schema drift in the concatenated `[rules]` tables.
fn validate_combined_manifest(ruleset_name: &str, combined: &str) -> Result<()> {
    let value: toml::Value = toml::from_str(combined).with_context(|| {
        format!(
            "Generated rules-all.toml for ruleset '{}' is not valid TOML \
             (likely a duplicate rule id or a malformed merged section)",
            ruleset_name
        )
    })?;
    if let Some(rules) = value.get("rules") {
        let _: ValidatedRulesTable = rules.clone().try_into().with_context(|| {
            format!(
                "Generated rules-all.toml for ruleset '{}' has an invalid [rules] schema",
                ruleset_name
            )
        })?;
    }
    Ok(())
}

fn generate_rules_all_toml() -> Result<()> {
    let rules_dir = PathBuf::from("src/rules");

    // Find all ruleset directories (direct children of src/rules/)
    let rulesets: Vec<PathBuf> = match fs::read_dir(&rules_dir) {
        Ok(entries) => entries
            .filter_map(|e| match e {
                Ok(entry) => Some(entry.path()),
                Err(err) => {
                    eprintln!("Warning: Skipping directory entry in src/rules: {}", err);
                    None
                }
            })
            .filter(|p| p.is_dir())
            .collect(),
        Err(e) => {
            eprintln!("Warning: Could not read src/rules directory: {}", e);
            return Ok(()); // Not fatal - continue build
        }
    };

    // Process each ruleset
    for ruleset_dir in rulesets {
        let ruleset_name = match ruleset_dir.file_name() {
            Some(name) => name.to_string_lossy().to_string(),
            None => {
                eprintln!(
                    "Warning: Invalid ruleset directory path: {}",
                    ruleset_dir.display()
                );
                continue;
            }
        };

        let output_path = ruleset_dir.join("rules-all.toml");

        // Collect all RULE-ID.toml files in this ruleset
        let mut toml_files: Vec<PathBuf> = WalkDir::new(&ruleset_dir)
            .into_iter()
            .filter_map(|e| match e {
                Ok(entry) => Some(entry),
                Err(err) => {
                    eprintln!(
                        "Warning: Skipping entry in {}: {}",
                        ruleset_dir.display(),
                        err
                    );
                    None
                }
            })
            .filter(|e| {
                e.path().is_file()
                    && e.path().extension().is_some_and(|ext| ext == "toml")
                    && e.path()
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name_str| {
                            // Match pattern like ARR30-C.toml, but exclude rules-all.toml
                            name_str != "rules-all.toml"
                                && name_str.contains('-')
                                && !name_str.starts_with('.')
                        })
            })
            .map(|e| e.path().to_path_buf())
            .collect();

        if toml_files.is_empty() {
            println!("No rule manifests found in ruleset: {}", ruleset_name);
            continue;
        }

        // Sort by rule ID for consistent output
        toml_files.sort();

        // Combine all TOML files - extract only the rules.cert_c section
        let mut combined_content = String::new();
        combined_content.push_str("# Auto-generated file - do not edit directly\n");
        combined_content.push_str(&format!(
            "# Generated from individual rule manifests in {}\n",
            ruleset_name
        ));
        combined_content.push_str("# To modify, edit the individual TOML files and rebuild\n");
        combined_content.push_str("# Full metadata is in individual rule TOML files\n\n");

        for toml_path in &toml_files {
            // Read full content — a rule manifest we cannot read is a hard error,
            // not a silently-skipped warning (the rule would vanish from the
            // generated manifest with no signal otherwise).
            let content = fs::read_to_string(toml_path)
                .with_context(|| format!("Failed to read rule manifest {}", toml_path.display()))?;

            // Validate before merging so syntax errors / schema violations /
            // malformed fields fail the build here instead of at runtime.
            validate_rule_manifest(toml_path, &content)?;

            // Extract the [rules.*] section (cert_c, brules, etc.)
            if let Some(start_idx) = content.find("[rules.") {
                let section_content = &content[start_idx..];

                // Find the end of this section (next section or end of file)
                let end_idx = section_content
                    .find("\n[")
                    .map(|i| i + 1)
                    .unwrap_or(section_content.len());

                let rule_section = &section_content[..end_idx];
                combined_content.push_str(rule_section);
                if !rule_section.ends_with('\n') {
                    combined_content.push('\n');
                }
                combined_content.push('\n');
            }
        }

        // Validate the merged output before writing it (catches duplicate rule
        // ids across files and any schema drift in the concatenation).
        validate_combined_manifest(&ruleset_name, &combined_content)?;

        // Write combined file
        let mut file = File::create(&output_path).context(format!(
            "Failed to create rules-all.toml at {}",
            output_path.display()
        ))?;

        file.write_all(combined_content.as_bytes())
            .context(format!(
                "Failed to write rules-all.toml to {}",
                output_path.display()
            ))?;

        println!("cargo:rerun-if-changed={}", ruleset_dir.display());
        println!(
            "Generated {} rules-all.toml with {} rule manifests",
            ruleset_name,
            toml_files.len()
        );
    }

    Ok(())
}

/// Regenerate `rules_templates/rules-all.toml` from the just-generated
/// `src/rules/cert_c/rules-all.toml` and `src/rules/cwe/rules-all.toml`. It is `include_str!`'d into the
/// aurora-lint binary as its built-in default manifest (`src/main.rs:
/// DEFAULT_MANIFEST_TOML`) and is also the full-mode Juliet manifest
/// (`bench/config.py: MANIFEST_JULIET_FULL`), so generating it here keeps both
/// current with every rule addition/removal instead of requiring a manual
/// resync step that's easy to forget.
///
/// **There is deliberately only one generated manifest.** A second,
/// benchmark-only copy used to be written alongside it with a hardcoded
/// 13-rule block (DCL04/DCL06/DCL08, EXP02/EXP10/EXP12/EXP14/EXP19,
/// INT01/INT02/INT16/INT17, PRE31) flipped to `enabled = false` on the
/// assumption that those rules were "too noisy on real codebases to be useful
/// signal". Because one constant flipped all 13 together, and because every
/// per-codebase real-world manifest was derived from that copy, the assumption
/// was never testable: the rules could not fire where the ground-truth oracle
/// could grade them. Measured on the two corpora that did keep them enabled it
/// is false for half of them -- six score 73 TP / 14 FP on pure-ftpd, the
/// best-precision rule group in the suite. A whole-rule disable that hides a
/// rule from the oracle is exactly what `conf/realworld/README.md` forbids.
///
/// So a suite-wide disable is not a thing this file can express any more. A
/// rule that does not apply to a codebase is disabled in that codebase's own
/// `conf/realworld/<cb>-rules.toml`, as an explicit `enabled = false` carrying
/// the reason. Do not reintroduce a curated second manifest here: it served
/// both the real-world base and the full-mode Juliet manifest, so a real-world
/// noise judgement silently moved a Juliet number.
fn sync_rules_templates() -> Result<()> {
    let src_path = PathBuf::from("src/rules/cert_c/rules-all.toml");
    let src_content = fs::read_to_string(&src_path)
        .with_context(|| format!("Failed to read {}", src_path.display()))?;

    let body_start = src_content.find("[rules.").ok_or_else(|| {
        anyhow::anyhow!("{} has no [rules.*] section to extract", src_path.display())
    })?;
    let mut body = src_content[body_start..].to_string();

    // The CWE ruleset ships enabled by default alongside CERT C: its rules
    // are detectors that moved out of `cert_c` when their ids turned out not
    // to be CERT C's, and moving them must not switch them off. (`brules`
    // stays opt-in, so it is not appended.)
    let cwe_path = PathBuf::from("src/rules/cwe/rules-all.toml");
    if let Ok(cwe_content) = fs::read_to_string(&cwe_path) {
        if let Some(start) = cwe_content.find("[rules.") {
            if !body.ends_with("\n\n") {
                body.push('\n');
            }
            body.push_str(&cwe_content[start..]);
        }
        println!("cargo:rerun-if-changed={}", cwe_path.display());
    }

    const HEADER: &str = "[metadata]\nname = \"CERT C Rules Configuration\"\nversion = \"1.0.0\"\ndescription = \"Configuration for CERT C coding standards compliance checking\"\ncert_version = \"2016\"\n\n";

    let all_path = PathBuf::from("rules_templates/rules-all.toml");
    fs::write(&all_path, format!("{}{}", HEADER, body))
        .with_context(|| format!("Failed to write {}", all_path.display()))?;

    println!("cargo:rerun-if-changed={}", src_path.display());
    println!("Synced {}", all_path.display());
    Ok(())
}

fn generate_integration_tests() -> Result<()> {
    let out_dir = std::env::var("OUT_DIR").context("OUT_DIR environment variable not set")?;
    let out_dir_path = PathBuf::from(&out_dir);

    // Create tests subdirectory
    let tests_dir = out_dir_path.join("tests");
    fs::create_dir_all(&tests_dir).context("Failed to create tests directory")?;

    // Track all rule modules for the main file
    let mut rule_modules = Vec::new();

    generate_cert_c_tests(&tests_dir, &mut rule_modules)?;
    generate_flat_ruleset_tests("brules", &tests_dir, &mut rule_modules)?;
    generate_flat_ruleset_tests("cwe", &tests_dir, &mut rule_modules)?;
    write_main_integration_file(&out_dir_path, &mut rule_modules)?;

    println!("cargo:rerun-if-changed=src/rules/cert_c");
    println!("cargo:rerun-if-changed=src/rules/brules");
    println!("cargo:rerun-if-changed=src/rules/cwe");
    println!("Generated {} per-rule test files", rule_modules.len());
    Ok(())
}

/// Walk `src/rules/cert_c/CATEGORY/RULE-ID` directories and emit per-rule test files.
fn generate_cert_c_tests(
    tests_dir: &std::path::Path,
    rule_modules: &mut Vec<String>,
) -> Result<()> {
    let cert_c_dir = PathBuf::from("src/rules/cert_c");

    // Walk through CATEGORY directories
    let category_entries = fs::read_dir(&cert_c_dir)
        .context("Failed to read src/rules/cert_c directory - does it exist?")?;

    for category_entry in category_entries {
        let category_entry = match category_entry {
            Ok(entry) => entry,
            Err(e) => {
                eprintln!("Warning: Skipping category entry: {}", e);
                continue;
            }
        };

        let category_path = category_entry.path();

        if !category_path.is_dir() {
            continue;
        }

        let category_name = match category_path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name,
            None => {
                eprintln!(
                    "Warning: Skipping category with invalid path: {}",
                    category_path.display()
                );
                continue;
            }
        };

        // Skip special directories
        if category_name == "tests" || category_name == "utils" || category_name.starts_with('.') {
            continue;
        }

        // Walk through RULE-ID directories
        let rule_entries = match fs::read_dir(&category_path) {
            Ok(entries) => entries,
            Err(e) => {
                eprintln!("Warning: Skipping category {}: {}", category_name, e);
                continue;
            }
        };

        for rule_entry in rule_entries {
            let rule_entry = match rule_entry {
                Ok(entry) => entry,
                Err(e) => {
                    eprintln!("Warning: Skipping rule entry in {}: {}", category_name, e);
                    continue;
                }
            };

            let rule_path = rule_entry.path();

            if !rule_path.is_dir() {
                continue;
            }

            let rule_id = match rule_path.file_name().and_then(|n| n.to_str()) {
                Some(id) => id,
                None => {
                    eprintln!(
                        "Warning: Skipping rule with invalid path: {}",
                        rule_path.display()
                    );
                    continue;
                }
            };

            let rule_base_path = format!("src/rules/cert_c/{}/{}", category_name, rule_id);
            let rule_tests_dir = rule_path.join("tests");

            if !rule_tests_dir.exists() {
                continue;
            }

            generate_rule_test_file(
                tests_dir,
                rule_id,
                &rule_base_path,
                &rule_tests_dir,
                rule_modules,
            )?;
        }
    }

    Ok(())
}

/// Walk `src/rules/<ruleset>/RULE-ID` directories (flat, no category level,
/// as `brules` and `cwe` are) and emit per-rule test files.
fn generate_flat_ruleset_tests(
    ruleset: &str,
    tests_dir: &std::path::Path,
    rule_modules: &mut Vec<String>,
) -> Result<()> {
    let ruleset_dir = PathBuf::from("src/rules").join(ruleset);
    if !ruleset_dir.exists() {
        return Ok(());
    }
    let Ok(rule_entries) = fs::read_dir(&ruleset_dir) else {
        return Ok(());
    };

    for rule_entry in rule_entries {
        let rule_entry = match rule_entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };

        let rule_path = rule_entry.path();
        if !rule_path.is_dir() {
            continue;
        }

        let rule_id = match rule_path.file_name().and_then(|n| n.to_str()) {
            Some(id) => id,
            None => continue,
        };

        let rule_base_path = format!("src/rules/{}/{}", ruleset, rule_id);
        let rule_tests_dir = rule_path.join("tests");
        if !rule_tests_dir.exists() {
            continue;
        }

        generate_rule_test_file(
            tests_dir,
            rule_id,
            &rule_base_path,
            &rule_tests_dir,
            rule_modules,
        )?;
    }

    Ok(())
}

/// Create one rule's per-rule test file, write its header, register the module, and
/// generate test functions for its `fail`, `expected_fail`, and `pass` directories.
fn generate_rule_test_file(
    tests_dir: &std::path::Path,
    rule_id: &str,
    rule_base_path: &str,
    rule_tests_dir: &std::path::Path,
    rule_modules: &mut Vec<String>,
) -> Result<()> {
    // Create per-rule test file
    let rule_snake = rule_id.to_lowercase().replace('-', "_");
    let rule_test_file = tests_dir.join(format!("{}_tests.rs", rule_snake));

    let mut rule_file = File::create(&rule_test_file).context(format!(
        "Failed to create test file for {}: {}",
        rule_id,
        rule_test_file.display()
    ))?;

    // Write per-rule file header (no use statements - they're in the main file)
    writeln!(rule_file, "// Auto-generated tests for {}", rule_id)?;
    writeln!(rule_file, "// DO NOT EDIT - Generated by build.rs\n")?;

    // Track this module for the main file
    rule_modules.push(rule_snake);

    for test_type in &["fail", "expected_fail", "pass"] {
        generate_subdir_tests(
            &mut rule_file,
            rule_id,
            rule_base_path,
            &rule_tests_dir.join(test_type),
            test_type,
        )?;
    }

    Ok(())
}

/// Generate a test function for every `.c` file in one test-type subdirectory
/// (`fail`/`expected_fail`/`pass`). Missing or unreadable directories are skipped.
fn generate_subdir_tests(
    rule_file: &mut File,
    rule_id: &str,
    rule_base_path: &str,
    subdir: &std::path::Path,
    test_type: &str,
) -> Result<()> {
    if !subdir.exists() {
        return Ok(());
    }

    let entries = match fs::read_dir(subdir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!(
                "Warning: Could not read {} directory for {}: {}",
                test_type, rule_id, e
            );
            return Ok(());
        }
    };

    for test_file in entries {
        let test_file = match test_file {
            Ok(file) => file,
            Err(e) => {
                eprintln!(
                    "Warning: Skipping test file in {}/{}: {}",
                    rule_id, test_type, e
                );
                continue;
            }
        };

        let test_path = test_file.path();

        if test_path.extension().is_some_and(|e| e == "c") {
            generate_test_function(rule_file, rule_id, rule_base_path, &test_path, test_type)
                .context(format!("Failed to generate test for {:?}", test_path))?;
        }
    }

    Ok(())
}

/// Generate the top-level `integration_tests.rs` that `include!()`s every per-rule file.
fn write_main_integration_file(
    out_dir_path: &std::path::Path,
    rule_modules: &mut [String],
) -> Result<()> {
    // Generate main integration_tests.rs with module includes using include!()
    let dest_path = out_dir_path.join("integration_tests.rs");
    let mut main_file =
        File::create(&dest_path).context("Failed to create integration_tests.rs")?;

    writeln!(main_file, "// Auto-generated test includes")?;
    writeln!(main_file, "// DO NOT EDIT - Generated by build.rs\n")?;
    writeln!(main_file, "#[cfg(test)]")?;
    writeln!(main_file, "mod generated_tests {{")?;

    // Sort for consistent output
    rule_modules.sort();

    for rule_module in rule_modules.iter() {
        // Use include!() to inline the test file contents
        writeln!(
            main_file,
            "    include!(concat!(env!(\"OUT_DIR\"), \"/tests/{}_tests.rs\"));",
            rule_module
        )?;
    }

    writeln!(main_file, "}}")?;
    Ok(())
}

fn generate_test_function(
    f: &mut File,
    rule_id: &str,
    rule_base_path: &str, // e.g. "src/rules/cert_c/EXP/EXP34-C" or "src/rules/brules/BRULE-065"
    test_path: &std::path::Path,
    test_type: &str, // "fail", "pass", or "expected_fail"
) -> Result<()> {
    // Convert rule_id to snake_case for function name
    let rule_snake = rule_id.to_lowercase().replace('-', "_");

    // Get test file name without extension
    let test_file_stem = test_path
        .file_stem()
        .and_then(|s| s.to_str())
        .context("Invalid test file name")?;
    let test_name_safe = test_file_stem.replace(['-', '.'], "_");

    // Generate test function name: test_arr00_c_fail_wiki_noncompliant_1
    let test_fn_name = format!("test_{}_{}_{}", rule_snake, test_type, test_name_safe);

    // Get relative path from project root
    let test_filename = test_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid test filename")?;
    let relative_path = format!("{}/tests/{}/{}", rule_base_path, test_type, test_filename);

    // Check if rule is implemented by reading the TOML file
    let toml_path = format!("{}/{}.toml", rule_base_path, rule_id);
    let is_enabled = check_if_rule_enabled(&toml_path)?;

    writeln!(f, "#[test]")?;
    writeln!(f, "#[allow(non_snake_case)]")?;

    // If rule is not enabled/implemented, mark test as ignored
    if !is_enabled {
        writeln!(f, "#[ignore = \"Rule {} not yet implemented\"]", rule_id)?;
    } else if test_type == "expected_fail" {
        writeln!(
            f,
            "#[ignore = \"Known limitation: {} cannot detect this pattern yet\"]",
            rule_id
        )?;
    }

    // The body is one call: the pipeline and the failure messages live once in
    // `run_fixture` (src/rules/cert_c/integration.rs). Inlining them into every
    // test made the generated code ~170K lines, and compiling that dominated
    // the test build's wall-clock and peak memory. An `expected_fail` fixture
    // asserts like a `fail` one; it is ignored above.
    //
    // Every fixture runs under each preset in `PRESETS` (ADR-0015: each
    // setting is validated like rule behavior), and under each preset in
    // `OPT_IN_PRESETS` its header names. The directory states the
    // expectation unless the header says otherwise; see `fixture_header`.
    let dir_expect = if test_type == "pass" {
        "Clean"
    } else {
        "Violation"
    };
    let header = fixture_header(test_path)?;
    let opted_in = OPT_IN_PRESETS
        .iter()
        .filter(|p| header.expect.iter().any(|(named, _)| named == *p));
    for preset in PRESETS.iter().chain(opted_in) {
        let expect = header
            .expect
            .iter()
            .find(|(p, _)| p == preset)
            .map_or(dir_expect, |(_, e)| e.as_str());
        // The default preset keeps the bare name, so a fixture's identity in
        // test output and the test summary does not change.
        let name = if *preset == "default" {
            test_fn_name.clone()
        } else {
            format!("{}__{}", test_fn_name, preset)
        };
        if *preset != "default" {
            writeln!(f, "#[test]")?;
            writeln!(f, "#[allow(non_snake_case)]")?;
            if !is_enabled {
                writeln!(f, "#[ignore = \"Rule {} not yet implemented\"]", rule_id)?;
            } else if test_type == "expected_fail" {
                writeln!(
                    f,
                    "#[ignore = \"Known limitation: {} cannot detect this pattern yet\"]",
                    rule_id
                )?;
            }
        }
        writeln!(
            f,
            "fn {}() {{ super::run_fixture({:?}, {:?}, {:?}, super::Expect::{}, {:?}, {:?}); }}",
            name, name, rule_id, relative_path, expect, preset, header.settings
        )?;
        writeln!(f)?;
    }

    Ok(())
}

/// The presets every fixture runs under. With [`OPT_IN_PRESETS`], must match
/// `settings::Preset`.
const PRESETS: &[&str] = &["default", "strict"];

/// The presets a fixture runs under only when its `Expect:` line names them.
/// The preset matrix covers only the rules whose verdict a preset changes
/// (ADR-0015, 2026-10-07 amendment, Decision 5), so a fixture whose header
/// does not name `pedantic` is not run under it.
const OPT_IN_PRESETS: &[&str] = &["pedantic"];

/// What a fixture's leading comment says about settings.
struct FixtureHeader {
    /// `Expect: default=clean strict=violation` -- per-preset expectations
    /// that override the directory's.
    expect: Vec<(String, String)>,
    /// `Settings: name=value, name=value` -- option overrides applied on top
    /// of each preset.
    settings: String,
}

/// Read a fixture's `Expect:` and `Settings:` lines from its leading comment
/// (everything before the first line of code). The grammar is strict so a
/// directive can never be silently ignored:
/// - a trailing `*/` is dropped, so `/* Expect: ... */` on one line works;
/// - a second `Expect:` or `Settings:` line is an error;
/// - a directive spelled in another case (`expect:`, `SETTINGS:`) is an error;
/// - a comment line carrying a directive after the first line of code is an
///   error (code such as `printf("Settings: ...")` is not a comment line and
///   is ignored).
fn fixture_header(path: &std::path::Path) -> Result<FixtureHeader> {
    let source = fs::read_to_string(path).with_context(|| format!("read {:?}", path))?;
    let mut header = FixtureHeader {
        expect: Vec::new(),
        settings: String::new(),
    };
    let (mut saw_expect, mut saw_settings, mut in_code) = (false, false, false);
    for (lineno, line) in source.lines().enumerate() {
        let t = line.trim();
        let is_comment_line = t.starts_with("/*") || t.starts_with('*') || t.starts_with("//");
        if !(t.is_empty() || is_comment_line) {
            in_code = true;
            continue;
        }
        let l = t.trim_start_matches(['*', '/', ' ']).trim();
        let l = l.strip_suffix("*/").map_or(l, str::trim_end);
        let directive = ["Expect:", "Settings:"].into_iter().find(|d| {
            l.get(..d.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(d))
        });
        let Some(directive) = directive else {
            continue;
        };
        let at = format!("{:?}:{}", path, lineno + 1);
        anyhow::ensure!(
            l.starts_with(directive),
            "{}: fixture directive must be spelled `{}`",
            at,
            directive
        );
        anyhow::ensure!(
            !in_code,
            "{}: `{}` must be in the fixture's leading comment, before any code",
            at,
            directive
        );
        let rest = &l[directive.len()..];
        if directive == "Expect:" {
            anyhow::ensure!(!saw_expect, "{}: a second `Expect:` line", at);
            saw_expect = true;
            for pair in rest.split_whitespace() {
                let (preset, outcome) = pair
                    .split_once('=')
                    .with_context(|| format!("{}: bad Expect entry '{}'", at, pair))?;
                anyhow::ensure!(
                    PRESETS.contains(&preset) || OPT_IN_PRESETS.contains(&preset),
                    "{}: Expect names unknown preset '{}'",
                    at,
                    preset
                );
                let outcome = match outcome {
                    "clean" => "Clean",
                    "violation" => "Violation",
                    _ => anyhow::bail!(
                        "{}: Expect outcome must be clean or violation, got '{}'",
                        at,
                        outcome
                    ),
                };
                header
                    .expect
                    .push((preset.to_string(), outcome.to_string()));
            }
        } else {
            anyhow::ensure!(!saw_settings, "{}: a second `Settings:` line", at);
            saw_settings = true;
            header.settings = rest.trim().to_string();
        }
    }
    Ok(header)
}

fn check_if_rule_enabled(toml_path: &str) -> Result<bool> {
    // Read the TOML file and check if rule is enabled
    let content = match fs::read_to_string(toml_path) {
        Ok(content) => content,
        Err(_) => return Ok(false), // If TOML file doesn't exist, assume not implemented
    };

    // Parse TOML properly using serde
    let config: RuleConfig = match toml::from_str(&content) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Warning: Failed to parse TOML {}: {}", toml_path, e);
            eprintln!("         Falling back to string matching");
            // Fallback to string matching if TOML parse fails
            return Ok(content.contains("[rules.") && content.contains("enabled = true"));
        }
    };

    // Check for implemented rule format: [rules.<namespace>.RULE-ID] enabled = true
    if let Some(rules) = config.rules {
        for namespace_rules in rules.values() {
            for settings in namespace_rules.values() {
                if settings.enabled {
                    return Ok(true);
                }
            }
        }
    }

    // Check for unimplemented rule format: [rule] enabled = false
    if let Some(rule_settings) = config.rule {
        return Ok(rule_settings.enabled);
    }

    // Default to false if format is unclear
    Ok(false)
}
