use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use walkdir::WalkDir;

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
// `src/manifest/mod.rs` (`RuleNamespaces` / `RuleConfig` / `Severity` /
// `RuleCategory`) so that a syntax error, an unknown/typo'd field, or an
// invalid enum value in an individual rule TOML is caught when `build.rs`
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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // fields exist only to enforce the schema during deserialize
struct ValidatedRuleConfig {
    enabled: bool,
    severity: Option<ValidatedSeverity>,
    description: Option<String>,
    category: Option<ValidatedCategory>,
    cert_id: Option<String>,
    parameters: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
enum ValidatedSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Deserialize)]
enum ValidatedCategory {
    Rule,
    Recommendation,
}

fn main() {
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
    // with src/rules/cert_c/rules-all.toml. Without this, newly added rules
    // silently never run for end users or in the real-world benchmark even
    // though they build and pass their own tests -- this exact drift went
    // unnoticed from v0.3.51 through v0.4.139 (26 rules missing).
    if let Err(e) = sync_rules_templates() {
        eprintln!("Error syncing rules_templates manifests: {}", e);
        std::process::exit(1);
    }

    // Generate integration tests from C test files
    if let Err(e) = generate_integration_tests() {
        eprintln!("Error generating integration tests: {}", e);
        std::process::exit(1);
    }
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
            "Invalid [rules] schema in {} (unknown/malformed field or bad severity/category value)",
            path.display()
        )
    })?;

    // 4. Exactly one rule, whose id matches the file name stem.
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid manifest file name: {}", path.display()))?;
    let ids: Vec<&String> = table.cert_c.keys().chain(table.brules.keys()).collect();
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

/// Rules the benchmark manifest disables while the CLI's default manifest
/// keeps them enabled. **Empty on purpose, and adding to it needs oracle
/// evidence.**
///
/// This list used to hold 13 rules (the DCL04/DCL06/DCL08, EXP02/EXP10/EXP12/
/// EXP14/EXP19, INT01/INT02/INT16/INT17, PRE31 block) on the assumption that
/// they were "too noisy on real codebases to be useful signal". Because one
/// constant flipped all 13 together, the same block was inherited verbatim by
/// every per-codebase manifest derived from this file, so the assumption was
/// never testable: the rules could not fire where the ground-truth oracle
/// could grade them.
///
/// Measured on the two corpora that did keep them enabled, the assumption is
/// false for half of them: six (DCL04-C, DCL06-C, EXP12-C, EXP14-C, EXP19-C,
/// INT17-C) score 73 TP / 14 FP on pure-ftpd, the best-precision rule group in
/// the suite, and the other six score 0 TP / 57 FP there -- unproductive, but
/// nowhere near enough volume to swamp a measurement. A whole-rule disable
/// that hides a rule from the oracle is exactly what `conf/realworld/README.md`
/// forbids, so the block is gone and every one of the 13 now runs on all nine
/// real-world corpora.
///
/// Consequence to know about: this file is also the full-mode Juliet manifest
/// (`bench/config.py: MANIFEST_ALL`), so emptying the list changes what a
/// `--full` Juliet run measures, and it makes rules-benchmark.toml identical to
/// rules-all.toml. Both are tracked as a follow-up.
const BENCHMARK_NOISE_DISABLED: &[&str] = &[];

/// Regenerate `rules_templates/rules-all.toml` (embedded into the aurora-lint binary
/// via `include_str!` as its built-in default manifest) and
/// `rules_templates/rules-benchmark.toml` (used by the real-world benchmark)
/// from the just-generated `src/rules/cert_c/rules-all.toml`, so both stay
/// current with every rule addition/removal instead of requiring a manual
/// resync step that's easy to forget.
fn sync_rules_templates() -> Result<()> {
    let src_path = PathBuf::from("src/rules/cert_c/rules-all.toml");
    let src_content = fs::read_to_string(&src_path)
        .with_context(|| format!("Failed to read {}", src_path.display()))?;

    let body_start = src_content.find("[rules.").ok_or_else(|| {
        anyhow::anyhow!("{} has no [rules.*] section to extract", src_path.display())
    })?;
    let body = &src_content[body_start..];

    const HEADER: &str = "[metadata]\nname = \"CERT C Rules Configuration\"\nversion = \"1.0.0\"\ndescription = \"Configuration for CERT C coding standards compliance checking\"\ncert_version = \"2016\"\n\n";

    // rules_templates/rules-all.toml: verbatim body under the existing header.
    let all_path = PathBuf::from("rules_templates/rules-all.toml");
    let all_content = format!("{}{}", HEADER, body);
    fs::write(&all_path, &all_content)
        .with_context(|| format!("Failed to write {}", all_path.display()))?;

    // rules_templates/rules-benchmark.toml: same body, with the noise-disabled
    // rules' `enabled = true` flipped to `enabled = false`.
    let mut bench_content = all_content;
    for rule_id in BENCHMARK_NOISE_DISABLED {
        let marker = format!("[rules.cert_c.{}]\nenabled = true", rule_id);
        let replacement = format!("[rules.cert_c.{}]\nenabled = false", rule_id);
        if bench_content.contains(&marker) {
            bench_content = bench_content.replace(&marker, &replacement);
        } else {
            eprintln!(
                "Warning: benchmark-noise rule '{}' not found in generated manifest (renamed/removed?)",
                rule_id
            );
        }
    }
    let bench_path = PathBuf::from("rules_templates/rules-benchmark.toml");
    fs::write(&bench_path, &bench_content)
        .with_context(|| format!("Failed to write {}", bench_path.display()))?;

    println!("cargo:rerun-if-changed={}", src_path.display());
    println!("Synced rules_templates/rules-all.toml and rules-benchmark.toml");
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
    generate_brules_tests(&tests_dir, &mut rule_modules)?;
    write_main_integration_file(&out_dir_path, &mut rule_modules)?;

    println!("cargo:rerun-if-changed=src/rules/cert_c");
    println!("cargo:rerun-if-changed=src/rules/brules");
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

/// Walk `src/rules/brules/RULE-ID` directories (flat, no category level) and emit
/// per-rule test files.
fn generate_brules_tests(
    tests_dir: &std::path::Path,
    rule_modules: &mut Vec<String>,
) -> Result<()> {
    let brules_dir = PathBuf::from("src/rules/brules");
    if !brules_dir.exists() {
        return Ok(());
    }
    let Ok(brule_entries) = fs::read_dir(&brules_dir) else {
        return Ok(());
    };

    for brule_entry in brule_entries {
        let brule_entry = match brule_entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };

        let rule_path = brule_entry.path();
        if !rule_path.is_dir() {
            continue;
        }

        let rule_id = match rule_path.file_name().and_then(|n| n.to_str()) {
            Some(id) => id,
            None => continue,
        };

        let rule_base_path = format!("src/rules/brules/{}", rule_id);
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
    writeln!(main_file, "    use crate::parser::CParser;")?;
    writeln!(main_file, "    use crate::rules::RuleRegistry;")?;
    writeln!(main_file, "    use std::path::Path;\n")?;

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

    // Single-file reproduce command + wiki-derived description, embedded into the
    // assertion message so a failing test points straight at its source and how
    // to re-run the rule against just that file (see generate_test_function below).
    let repro_path = escape_for_format_literal(&relative_path);
    let about_clause = match extract_test_description(test_path) {
        Some(desc) => format!("\\n  about:     {}", escape_for_format_literal(&desc)),
        None => String::new(),
    };

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
    writeln!(f, "fn {}() {{", test_fn_name)?;
    writeln!(f, "    let registry = RuleRegistry::new();")?;
    writeln!(
        f,
        "    let rule = registry.get_rule(\"{}\").expect(\"Rule {} not found in registry\");",
        rule_id, rule_id
    )?;
    writeln!(f, "    ")?;
    writeln!(
        f,
        "    let test_path = Path::new(env!(\"CARGO_MANIFEST_DIR\")).join(\"{}\");",
        relative_path
    )?;
    writeln!(f, "    let source = std::fs::read_to_string(&test_path)")?;
    writeln!(
        f,
        "        .unwrap_or_else(|e| panic!(\"Failed to read {{:?}}: {{}}\", test_path, e));"
    )?;
    writeln!(f, "    ")?;
    writeln!(
        f,
        "    let mut parser = CParser::new().expect(\"Failed to create parser\");"
    )?;
    writeln!(f, "    let (tree, source) = parser.parse_source(&source)")?;
    writeln!(
        f,
        "        .unwrap_or_else(|e| panic!(\"Failed to parse {{:?}}: {{}}\", test_path, e));"
    )?;
    writeln!(f, "    ")?;

    // Every fixture is analysed with the context the shipped scan builds for it:
    // a prescan of the file itself (what `-d` gives a real run -- see
    // `prescan_single_file`), then CFGs and VRA through the same
    // `build_file_analysis` the scan calls. Both come from the scan's own code
    // rather than a test-only reimplementation of it. There is no opt-in: a
    // fixture checked without context exercises an analysis strictly weaker than
    // anything the tool ships, and a green result under it says nothing about
    // what a real scan does.
    writeln!(
        f,
        "    let context = crate::analyze::prescan::prescan_single_file(&test_path, rule.needs_vra())"
    )?;
    writeln!(
        f,
        "        .unwrap_or_else(|e| panic!(\"Failed to prescan {{:?}}: {{}}\", test_path, e));"
    )?;
    writeln!(f, "    rule.set_project_context(&context);")?;
    writeln!(f, "    let analysis = crate::analyze::build_file_analysis(")?;
    writeln!(f, "        &tree.root_node(),")?;
    writeln!(f, "        &source,")?;
    writeln!(f, "        &context,")?;
    writeln!(f, "        rule.needs_vra(),")?;
    writeln!(f, "    );")?;
    writeln!(f, "    analysis.apply_to(rule);")?;
    writeln!(f, "    ")?;

    writeln!(
        f,
        "    let violations = rule.check(&tree.root_node(), &source);"
    )?;
    writeln!(f, "    ")?;

    if test_type == "fail" || test_type == "expected_fail" {
        writeln!(f, "    let detected_violation = !violations.is_empty();")?;
        writeln!(f, "    ")?;
        writeln!(f, "    // Record result for report generation")?;
        if test_type == "expected_fail" {
            writeln!(f, "    // For expected_fail tests: known limitation — violation expected but tool cannot detect it yet")?;
        } else {
            writeln!(f, "    // For fail tests: we expect violations to be detected (detected_violation should be true)")?;
        }
        writeln!(
            f,
            "    super::record_test_result(\"{}\", detected_violation, true);",
            test_fn_name
        )?;
        writeln!(f, "    ")?;
        writeln!(f, "    assert!(")?;
        writeln!(f, "        detected_violation,")?;
        // Clickable `source: <abs path>:1` plus a copy-paste reproduce command so a
        // missing-detection failure links straight back to the fixture and the rule.
        writeln!(
            f,
            "        \"\\n[{rule_id}] expected a violation in this FAIL test, but none was detected.\\n  \
             source:    {{}}:1\\n  reproduce: cargo run -- --rules {rule_id} {repro}{about}\\n\",",
            rule_id = rule_id,
            repro = repro_path,
            about = about_clause
        )?;
        writeln!(f, "        test_path.display()")?;
        writeln!(f, "    );")?;
    } else {
        writeln!(f, "    let no_violation = violations.is_empty();")?;
        writeln!(f, "    ")?;
        writeln!(f, "    // Record result for report generation")?;
        writeln!(f, "    // For pass tests: we expect NO violations to be detected (no_violation should be true)")?;
        writeln!(
            f,
            "    super::record_test_result(\"{}\", no_violation, false);",
            test_fn_name
        )?;
        writeln!(f, "    ")?;
        // Surface the exact false-positive location (`<abs path>:<line>`) and message
        // so the failing assertion is a clickable jump to the offending source line.
        writeln!(f, "    let fp = violations.first();")?;
        writeln!(f, "    let fp_line = fp.map(|v| v.line).unwrap_or(0);")?;
        writeln!(
            f,
            "    let fp_msg = fp.map(|v| v.message.as_str()).unwrap_or(\"unknown\");"
        )?;
        writeln!(f, "    assert!(")?;
        writeln!(f, "        no_violation,")?;
        writeln!(
            f,
            "        \"\\n[{rule_id}] FALSE POSITIVE in this PASS test ({{}} finding(s)).\\n  \
             at:        {{}}:{{}}\\n  message:   {{}}\\n  reproduce: cargo run -- --rules {rule_id} {repro}{about}\\n\",",
            rule_id = rule_id,
            repro = repro_path,
            about = about_clause
        )?;
        writeln!(
            f,
            "        violations.len(), test_path.display(), fp_line, fp_msg"
        )?;
        writeln!(f, "    );")?;
    }

    writeln!(f, "}}")?;
    writeln!(f)?;

    Ok(())
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

/// Extract a human-readable description from a test `.c` file's header block.
///
/// CERT C test fixtures (mostly scraped from the CERT wiki) start with a banner
/// comment containing `Description:` and/or `Source:` lines. Surfacing that text
/// in the assertion failure message links a failing test straight back to the
/// wiki example it was derived from, without the developer having to open the file.
fn extract_test_description(test_path: &std::path::Path) -> Option<String> {
    let content = fs::read_to_string(test_path).ok()?;
    let mut source: Option<String> = None;
    // Only the leading banner comment matters; bail out once real code starts.
    for line in content.lines().take(20) {
        let l = line.trim().trim_start_matches(['*', '/', ' ']).trim();
        if let Some(rest) = l.strip_prefix("Description:") {
            let d = rest.trim();
            if !d.is_empty() {
                return Some(d.to_string());
            }
        } else if let Some(rest) = l.strip_prefix("Source:") {
            let s = rest.trim();
            if !s.is_empty() {
                source = Some(s.to_string());
            }
        }
    }
    source.map(|s| format!("{} example", s))
}

/// Escape a string so it can be embedded verbatim *inside* a Rust `format!`
/// string literal: escape backslashes/quotes, flatten whitespace, and double
/// braces so any `{`/`}` in the text is not parsed as a format placeholder.
fn escape_for_format_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' | '\t' | '\r' => out.push(' '),
            '{' => out.push_str("{{"),
            '}' => out.push_str("}}"),
            c => out.push(c),
        }
    }
    out
}
