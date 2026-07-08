#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::collapsible_if)]

pub mod prelude;

mod analyze;
mod export;
mod files;
mod manifest;
mod parser;
mod progress;
mod rules;
mod toolchain;
#[cfg(feature = "tui")]
mod ui;
mod utility;

use crate::manifest::Severity;
use crate::prelude::*;
use clap::{Arg, Command};

use analyze::{analyze_project, handle_generate_suppression};
use export::export_all_violations;
use files::ProjectSource;
use progress::CLIProgressReporter;
#[cfg(feature = "tui")]
use ui::TerminalUI;

use std::collections::HashSet;
use std::fs;
use std::path::Path;

fn main() {
    let result = run();
    match result {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(e) => {
            eprintln!("Error: {:#}", e);
            std::process::exit(2);
        }
    }
}

fn run() -> Result<i32> {
    let matches = Command::new("sqc")
        .about("Software Code Quality - CERT C compliance checker")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::new("path")
                .help("Path to the file, directory, or git repository to analyze")
                .value_name("PATH")
                .default_value(".")
                .index(1),
        )
        .arg(
            Arg::new("manifest")
                .long("manifest")
                .short('m')
                .help("Path to the rules manifest file")
                .value_name("FILE")
                .default_value("rules_templates/rules-all.toml"),
        )
        .arg(
            Arg::new("interactive")
                .long("interactive")
                .short('i')
                .help("Run in interactive terminal UI mode (requires building with `--features tui`)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("export")
                .long("export")
                .short('e')
                .help("Export violations to file (CSV, Excel, JSON, or SARIF based on extension)")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("generate_suppression")
                .long("generate-suppression")
                .help("Generate suppression comment for a specific file:line:rule")
                .value_name("FILE:LINE:RULE")
                .conflicts_with("interactive")
                .conflicts_with("export"),
        )
        .arg(
            Arg::new("directories")
                .long("directories")
                .short('d')
                .help("Additional directories to pre-scan for function definitions (cross-file context)")
                .value_name("DIR")
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("include_paths")
                .long("include-path")
                .short('I')
                .help("Include search paths for resolving #include directives (like compiler -I flag)")
                .value_name("DIR")
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("exclude")
                .long("exclude")
                .help("Exclude files matching this path glob from analysis (repeatable, e.g. --exclude '**/onelua.c' --exclude 'testes/**')")
                .value_name("GLOB")
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("fail_on_violation")
                .long("fail-on-violation")
                .help("Exit with code 1 if any violations are found")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("fail_on_severity")
                .long("fail-on-severity")
                .help("Exit with code 1 if any violation meets or exceeds this severity")
                .value_name("LEVEL")
                .value_parser(["Low", "Medium", "High", "Critical"]),
        )
        .arg(
            Arg::new("min_severity")
                .long("min-severity")
                .help("Only report violations at or above this severity")
                .value_name("LEVEL")
                .value_parser(["Low", "Medium", "High", "Critical"]),
        )
        .arg(
            Arg::new("rules")
                .long("rules")
                .help("Only report violations from these rules (comma-separated)")
                .value_name("RULE1,RULE2,..."),
        )
        .arg(
            Arg::new("diff")
                .long("diff")
                .help("Only analyze modified/new C files (git diff)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("suppress_file")
                .long("suppress-file")
                .help("Path to suppress.toml file (auto-detected as suppress.toml or the legacy .sqc-suppress.toml in project root if not specified)")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .help("Increase output verbosity (-v: per-rule scanning progress)")
                .action(clap::ArgAction::Count),
        )
        .arg(
            Arg::new("save_prescan")
                .long("save-prescan")
                .help("Save prescan context to a binary cache file (for CI/CD caching)")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("load_prescan")
                .long("load-prescan")
                .help("Load prescan context from cache instead of scanning -d directories")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("jobs")
                .long("jobs")
                .short('j')
                .help("Number of parallel analysis threads (0 = auto-detect, 1 = sequential)")
                .value_name("N")
                .default_value("0")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("detect_relevance")
                .long("detect-relevance")
                .help("Detect categorically-inapplicable rule classes (CON*/WIN*) in PATH and -d directories, then write a relevance-gated manifest with --write-manifest. Does not run an analysis.")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("write_manifest")
                .long("write-manifest")
                .help("With --detect-relevance: write the generated manifest here (requires --detect-relevance)")
                .value_name("FILE")
                .requires("detect_relevance"),
        )
        .get_matches();

    let path = matches.get_one::<String>("path").unwrap();
    let manifest_path = matches.get_one::<String>("manifest").unwrap();
    let interactive = matches.get_flag("interactive");
    let export_file = matches.get_one::<String>("export");
    let generate_suppression = matches.get_one::<String>("generate_suppression");
    let directories: Vec<String> = matches
        .get_many::<String>("directories")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();
    let include_paths: Vec<String> = matches
        .get_many::<String>("include_paths")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();
    let excludes: Vec<String> = matches
        .get_many::<String>("exclude")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();
    let fail_on_violation = matches.get_flag("fail_on_violation");
    let fail_on_severity: Option<Severity> = matches
        .get_one::<String>("fail_on_severity")
        .map(|s| s.parse().expect("clap validated severity"));
    let min_severity: Option<Severity> = matches
        .get_one::<String>("min_severity")
        .map(|s| s.parse().expect("clap validated severity"));
    let rule_filter: Option<HashSet<String>> = matches
        .get_one::<String>("rules")
        .map(|s| s.split(',').map(|r| r.trim().to_string()).collect());
    let diff_only = matches.get_flag("diff");
    let suppress_file = matches.get_one::<String>("suppress_file");
    let verbosity = matches.get_count("verbose");
    let save_prescan = matches.get_one::<String>("save_prescan");
    let load_prescan = matches.get_one::<String>("load_prescan");
    let jobs = *matches.get_one::<usize>("jobs").unwrap();
    let detect_relevance = matches.get_flag("detect_relevance");
    let write_manifest = matches.get_one::<String>("write_manifest");

    if detect_relevance {
        let mut corpus = vec![path.clone()];
        corpus.extend(directories.iter().cloned());
        let profile = analyze::relevance::detect(&corpus)?;
        println!(
            "Detected: threading={}, windows={}, max_c_standard={:?}",
            profile.has_threading, profile.has_windows, profile.max_c_standard
        );

        let base_manifest = RuleManifest::load(manifest_path)?;
        let generated = analyze::relevance::generate_manifest_toml(&base_manifest, &profile);

        match write_manifest {
            Some(out_path) => {
                fs::write(out_path, &generated)?;
                println!("Wrote relevance-gated manifest to: {}", out_path);
            }
            None => print!("{}", generated),
        }
        return Ok(0);
    }

    // Verify the path and determine source type
    let project_source = ProjectSource::open(path)?;
    println!("Detected {} at: {}", project_source.source_type(), path);

    let manifest = RuleManifest::load(manifest_path)?;

    // Handle suppression generation
    if let Some(gen_spec) = generate_suppression {
        handle_generate_suppression(gen_spec)?;
        return Ok(0);
    }

    if interactive {
        #[cfg(feature = "tui")]
        {
            let mut ui = TerminalUI::new(path, manifest, &directories, &include_paths)?;
            ui.run()?;
            return Ok(0);
        }
        #[cfg(not(feature = "tui"))]
        {
            anyhow::bail!(
                "sqc was built without the `tui` feature; rebuild with `cargo build --features tui` to use --interactive"
            );
        }
    }

    println!("Analyzing {} at: {}", project_source.source_type(), path);
    println!("Using manifest: {}", manifest_path);

    if diff_only {
        println!("Mode: diff-only (analyzing modified files)");
    }

    // Create progress reporter for CLI
    let progress_reporter = CLIProgressReporter::new(verbosity);

    // Perform analysis with progress reporting
    let results = analyze_project(
        &project_source,
        &manifest,
        Some(&progress_reporter),
        &directories,
        &include_paths,
        &excludes,
        diff_only,
        suppress_file.map(|s| s.as_str()),
        save_prescan.map(|s| s.as_str()),
        load_prescan.map(|s| s.as_str()),
        jobs,
    )?;

    let mut violations = results.violations;
    let suppressed = results.suppressed;

    // Post-analysis filtering
    if let Some(ref min_sev) = min_severity {
        violations.retain(|v| v.severity >= *min_sev);
    }
    if let Some(ref rules) = rule_filter {
        violations.retain(|v| rules.contains(&v.rule_id));
    }

    // Print violations to stdout
    let cwd = std::env::current_dir().unwrap_or_default();
    for v in &violations {
        let display_path = Path::new(&v.file_path)
            .strip_prefix(&cwd)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| v.file_path.clone());
        let sev = if v.needs_manual_review() {
            format!("{}?", v.severity.to_string().to_lowercase())
        } else {
            v.severity.to_string().to_lowercase()
        };
        println!(
            "{}:{}:{}: [{}] {}: {}",
            display_path, v.line, v.column, sev, v.rule_id, v.message
        );
        if let Some(ref hint) = v.suggestion {
            println!("  note: {}", hint);
        }
    }

    // Export to file if requested (includes both active and suppressed violations)
    if let Some(export_path) = export_file {
        export_all_violations(&violations, &suppressed, export_path, &manifest)?;
        println!(
            "Exported {} violations ({} suppressed) to: {}",
            violations.len(),
            suppressed.len(),
            export_path
        );
    }

    // Print summary
    println!(
        "Total violations: {} ({} suppressed)",
        violations.len(),
        suppressed.len()
    );

    // Determine exit code (only unsuppressed violations count)
    if fail_on_violation && !violations.is_empty() {
        return Ok(1);
    }
    if let Some(ref threshold) = fail_on_severity {
        if violations.iter().any(|v| v.severity >= *threshold) {
            return Ok(1);
        }
    }

    Ok(0)
}
