#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::collapsible_if)]

// The CLI is a thin wrapper over the `aurora_lint` library crate. Declaring
// the modules here again (`mod rules;` etc.) would compile the whole engine a
// second time, and `cargo test` would build and run every test twice.
#[cfg(feature = "tui")]
use aurora_lint::ui;
use aurora_lint::{analyze, export, files, manifest, progress, settings};

use anyhow::Context;
use aurora_lint::prelude::*;
use clap::{Arg, Command};
use manifest::Severity;
use settings::{AnalysisSettings, SettingsConfig};

use analyze::{analyze_project, handle_generate_suppression};
use export::export_all_violations;
use files::ProjectSource;
use progress::CLIProgressReporter;
#[cfg(feature = "tui")]
use ui::TerminalUI;

use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Embedded at compile time so `aurora-lint` works when installed outside the repo
/// checkout (e.g. via `cargo install`), where `rules_templates/rules-all.toml`
/// doesn't exist on disk relative to the binary.
const DEFAULT_MANIFEST_TOML: &str = include_str!("../rules_templates/rules-all.toml");

fn load_manifest(manifest_path: Option<&String>) -> Result<RuleManifest> {
    match manifest_path {
        Some(path) => RuleManifest::load(path),
        None => RuleManifest::from_toml_str(DEFAULT_MANIFEST_TOML)
            .context("Failed to parse built-in default manifest"),
    }
}

/// Which files the scan leaves out: the command line's `--exclude-all`,
/// `--report-exclude` and `--prescan-exclude`, plus the manifest's `[scope]`.
/// The deprecated `--exclude` keeps the meaning it always had, which is
/// `--report-exclude`'s, so no existing command line changes its findings.
fn scan_scope(matches: &clap::ArgMatches, manifest: &RuleManifest) -> analyze::ScanScope {
    let cli = |id: &str| -> Vec<String> {
        matches
            .get_many::<String>(id)
            .into_iter()
            .flatten()
            .cloned()
            .collect()
    };
    let deprecated = cli("exclude");
    if !deprecated.is_empty() {
        eprintln!(
            "Warning: --exclude is deprecated; it means --report-exclude (no findings, still \
             read for cross-file facts). Use --report-exclude, or --exclude-all to leave files \
             out of everything."
        );
    }
    let with = |mut globs: Vec<String>, from_manifest: &[String]| {
        globs.extend(from_manifest.iter().cloned());
        globs
    };
    analyze::ScanScope {
        exclude_all: with(cli("exclude_all"), &manifest.scope.exclude_all),
        report_exclude: with(
            [deprecated, cli("report_exclude")].concat(),
            &manifest.scope.report_exclude,
        ),
        prescan_exclude: with(cli("prescan_exclude"), &manifest.scope.prescan_exclude),
    }
}

/// The settings the command line states, to layer over the manifest's, and
/// one message per flag that does not parse. Every flag is read even after a
/// bad one, so `--check-config` can name each problem.
fn parse_settings_from_cli(matches: &clap::ArgMatches) -> (SettingsConfig, Vec<String>) {
    let parse = |id: &str| matches.get_one::<String>(id).map(String::as_str);
    let mut problems: Vec<String> = Vec::new();
    let mut config = SettingsConfig::default();
    let mut note = |what: &str, e: String| problems.push(format!("{what}: {e}"));
    if let Some(value) = parse("profile") {
        match value.parse() {
            Ok(p) => config.profile = Some(p),
            Err(e) => note("--profile", e),
        }
    }
    if let Some(value) = parse("policy") {
        match value.parse() {
            Ok(level) => config.policy.get_or_insert_with(Default::default).level = Some(level),
            Err(e) => note("--policy", e),
        }
    }
    if let Some(value) = parse("environment") {
        match value.parse() {
            Ok(kind) => config.environment.get_or_insert_with(Default::default).kind = Some(kind),
            Err(e) => note("--environment", e),
        }
    }
    if let Some(value) = parse("libc") {
        match value.parse() {
            Ok(libc) => config.environment.get_or_insert_with(Default::default).libc = Some(libc),
            Err(e) => note("--libc", e),
        }
    }
    if let Some(value) = parse("include_names") {
        match value.parse() {
            Ok(names) => {
                config
                    .environment
                    .get_or_insert_with(Default::default)
                    .include_names = Some(names)
            }
            Err(e) => note("--include-names", e),
        }
    }
    if let Some(value) = parse("data_model") {
        match value.parse() {
            Ok(model) => {
                config
                    .environment
                    .get_or_insert_with(Default::default)
                    .data_model = Some(model)
            }
            Err(e) => note("--data-model", e),
        }
    }
    for assignment in matches.get_many::<String>("set").into_iter().flatten() {
        if let Err(e) = config.set(assignment) {
            note("--set", format!("{e:#}"));
        }
    }
    for value in matches
        .get_many::<String>("allocator")
        .into_iter()
        .flatten()
    {
        match settings::memory::parse_allocator_flag(value) {
            Ok((name, contract)) => {
                config
                    .environment
                    .get_or_insert_with(Default::default)
                    .allocators
                    .insert(name, contract);
            }
            Err(e) => note("--allocator", format!("{e:#}")),
        }
    }
    for value in matches
        .get_many::<String>("deallocator")
        .into_iter()
        .flatten()
    {
        match settings::memory::parse_deallocator_flag(value) {
            Ok((name, arg)) => {
                config
                    .environment
                    .get_or_insert_with(Default::default)
                    .deallocators
                    .insert(name, arg);
            }
            Err(e) => note("--deallocator", format!("{e:#}")),
        }
    }
    (config, problems)
}

/// The settings the command line states, refused when any flag does not parse.
fn settings_from_cli(matches: &clap::ArgMatches) -> Result<SettingsConfig> {
    let (config, problems) = parse_settings_from_cli(matches);
    if problems.is_empty() {
        Ok(config)
    } else {
        anyhow::bail!("{}", problems.join("\n"))
    }
}

/// The manifest's settings with the command line's layered over them.
///
/// A `--profile` on the command line restarts from that preset: the
/// manifest's own axis settings and overrides would otherwise silently
/// survive a request for the strict preset. The manifest's declared
/// allocators and deallocators are facts about the project, not a policy
/// choice, and survive it (`SettingsConfig::project_facts`).
///
/// A compile database written for cl (`msvc_db`) declares a toolchain that
/// matches `#include` names case-insensitively; an explicit `include_names`
/// in either layer still wins.
fn resolve_settings(
    manifest: &RuleManifest,
    cli: &SettingsConfig,
    msvc_db: bool,
) -> Result<AnalysisSettings> {
    let mut config = if cli.profile.is_some() {
        manifest.settings_config().project_facts()
    } else {
        manifest.settings_config()
    };
    config.overlay(cli);
    if msvc_db {
        config.default_include_names(settings::IncludeNames::CaseInsensitive);
    }
    AnalysisSettings::resolve(&config).context("invalid policy/environment settings")
}

fn main() {
    // rayon's global pool runs the cross-file prescan and the macro-gap
    // audit, whose walks recurse once per AST nesting level; with the 2 MiB
    // default stack a deeply nested file aborted any multi-file scan. Give it
    // the scan pool's stack, before anything can start the pool.
    if let Err(e) = rayon::ThreadPoolBuilder::new()
        .stack_size(analyze::WORKER_STACK_BYTES)
        .build_global()
    {
        eprintln!(
            "Warning: rayon's global thread pool was already started ({e}); \
             deeply nested sources may overflow its default stack"
        );
    }
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
    let matches = Command::new("aurora-lint")
        .about("aurora-lint - a fast CERT C static analyzer")
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
                .help("Path to the rules manifest file (defaults to the built-in manifest)")
                .value_name("FILE"),
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
                .help("Export violations to file: .sarif (SARIF 2.1.0) or .json")
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
            Arg::new("compile_commands")
                .long("compile-commands")
                .help("Read include search paths, -D macros and the build's declared macro state from a compile_commands.json (optional; improves cross-file macro/header coverage, and resolves a name defined in several #if arms to the one this build compiles). Never suppresses findings by configuration")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("system_includes")
                .long("system-includes")
                .help("Also search the compiler's own built-in system header directories, found by asking it (cc -E -Wp,-v -). Off by default: it spawns a compiler. Works with or without --compile-commands, which can never contain these paths")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("report_macro_gaps")
                .long("report-macro-gaps")
                .help("After the scan, report where the macro-expansion engine was blind: macro definitions it skipped (variadic, #/##, platform-dead, ambiguous or conflicting), #includes it could not resolve, and calls it could not expand or attribute. Prints a summary to stdout; --report-macro-gaps=FILE also writes every row as JSON. Never changes a finding")
                .value_name("JSON_FILE")
                .num_args(0..=1)
                .default_missing_value("")
                .require_equals(true),
        )
        .arg(
            Arg::new("exclude_all")
                .long("exclude-all")
                .help("Leave files matching this path glob out of everything: not scanned, not reported, and not read for cross-file facts (repeatable, e.g. --exclude-all '**/onelua.c' --exclude-all 'testes/**')")
                .value_name("GLOB")
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("report_deallocator_candidates")
                .long("report-deallocator-candidates")
                .help("After the scan, list callees worth declaring as deallocators: each is shaped like one by name (*_free, destroy_*, ...), nothing in the scan shows it freeing anything, and an allocation handed to it was reported leaked by MEM31-C. Declare the real ones under [environment.deallocators] or with --deallocator. Prints a summary to stdout; --report-deallocator-candidates=FILE also writes every row as JSON. Never changes a finding")
                .value_name("JSON_FILE")
                .num_args(0..=1)
                .default_missing_value("")
                .require_equals(true),
        )
        .arg(
            Arg::new("exclude")
                .long("exclude")
                .help("Deprecated: same as --report-exclude. Use --report-exclude, or --exclude-all to leave files out of everything (repeatable)")
                .value_name("GLOB")
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("report_exclude")
                .long("report-exclude")
                .help("Report nothing in files matching this path glob, but still read them for cross-file facts: vendored code the product links (repeatable)")
                .value_name("GLOB")
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("prescan_exclude")
                .long("prescan-exclude")
                .help("Scan and report files matching this path glob, but do not read them for cross-file facts: stubs and alternate-platform files that do not link into the product (repeatable)")
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
                .help("Path to suppress.toml file (auto-detected in project root as suppress.toml, then the legacy .aurora-lint-suppress.toml / .sqc-suppress.toml, if not specified)")
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
            Arg::new("rule_step_limit")
                .long("rule-step-limit")
                .help(
                    "Steps one rule's check of one file (or one file's analysis) may take \
                     before it is stopped and reported, exit 3 (0 = no limit). Deterministic; \
                     see docs/error-handling.rst",
                )
                .value_name("N")
                .default_value(&*Box::leak(analyze::containment::DEFAULT_STEP_LIMIT.to_string().into_boxed_str()))
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("rule_time_limit")
                .long("rule-time-limit")
                .help(
                    "Seconds one rule's check of one file (or one file's analysis) may run \
                     before it is stopped and reported, exit 3 (0 = no limit). The last \
                     resort against a hang; see docs/error-handling.rst",
                )
                .value_name("SECS")
                .default_value(&*Box::leak(analyze::containment::DEFAULT_TIME_LIMIT_SECS.to_string().into_boxed_str()))
                .value_parser(clap::value_parser!(u64)),
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
            Arg::new("profile")
                .long("profile")
                .help("Preset for both settings axes: default (default policy, hosted) or strict (strict policy, freestanding). Overrides the manifest's `profile`")
                .value_name("PRESET")
                .value_parser(["default", "strict"]),
        )
        .arg(
            Arg::new("policy")
                .long("policy")
                .help("Policy axis: which findings are reported (overrides the preset)")
                .value_name("POLICY")
                .value_parser(["default", "strict"]),
        )
        .arg(
            Arg::new("environment")
                .long("environment")
                .help("Environment axis: the implementation the code runs under (overrides the preset). Declared, never inferred from the scanning host")
                .value_name("KIND")
                .value_parser(["hosted", "freestanding"]),
        )
        .arg(
            Arg::new("libc")
                .long("libc")
                .help("C library model whose documented contracts are trusted")
                .value_name("MODEL")
                .value_parser(["iso-posix", "glibc", "musl", "newlib", "picolibc", "custom"]),
        )
        .arg(
            Arg::new("include_names")
                .long("include-names")
                .help("How #include names match files: exact, or case-insensitive as cl does on Windows. Default: case-insensitive with an MSVC --compile-commands database, exact otherwise; never taken from the scanning host")
                .value_name("MODE")
                .value_parser(["exact", "case-insensitive"]),
        )
        .arg(
            Arg::new("data_model")
                .long("data-model")
                .help("The data model: the bundle of integer facts the code is built for: iso (default: loads nothing, so only the widths ISO C guarantees and limit macros such as INT_MAX are unknown), ilp32, lp64 or llp64; override one fact with --set int_bits=16 (also short_bits, long_bits, long_long_bits, pointer_bits, wchar_t_bits, char_signed)")
                .value_name("MODEL")
                .value_parser(["iso", "ilp32", "lp64", "llp64"]),
        )
        .arg(
            Arg::new("allocator")
                .long("allocator")
                .help("Declare a function the scan cannot see into as an allocator following the named standard allocator's contract (malloc, calloc, realloc, aligned_alloc, strdup, strndup; default malloc). Repeatable; same as [environment.allocators] in the manifest")
                .value_name("NAME[=CONTRACT]")
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("deallocator")
                .long("deallocator")
                .help("Declare a function the scan cannot see into as freeing its ARG-th argument (default 1). Repeatable; same as [environment.deallocators] in the manifest")
                .value_name("NAME[=ARG]")
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("set")
                .long("set")
                .help("Override one named option (repeatable); see --list-options")
                .value_name("NAME=VALUE")
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("check_config")
                .long("check-config")
                .action(clap::ArgAction::SetTrue)
                .help(
                    "Resolve the settings from the manifest and the command line exactly as a \
                     scan would, validate them, and exit: 0 and one line when valid, nonzero \
                     with one error per problem otherwise. Scans no files",
                ),
        )
        .arg(
            Arg::new("write_config")
                .long("write-config")
                .help(
                    "Write a complete, commented configuration file for the current settings \
                     (the manifest, --data-model and --set applied) and exit: every key with a \
                     one-line description, a key at its default commented out. Refuses to \
                     overwrite FILE unless --overwrite is given; '-' writes to stdout",
                )
                .value_name("FILE"),
        )
        .arg(
            Arg::new("overwrite")
                .long("overwrite")
                .help("With --write-config: replace FILE if it exists")
                .action(clap::ArgAction::SetTrue)
                .requires("write_config"),
        )
        .arg(
            Arg::new("list_options")
                .long("list-options")
                .help("List every policy and environment option with its value under each preset and the current settings, then exit")
                .value_name("FORMAT")
                .num_args(0..=1)
                .default_missing_value("text")
                .value_parser(["text", "json", "rst"]),
        )
        .arg(
            Arg::new("list_rules")
                .long("list-rules")
                .help("List every rule the tool ships and whether the configuration enables it, then the rules it no longer ships and why, then exit")
                .value_name("FORMAT")
                .num_args(0..=1)
                .default_missing_value("text")
                .value_parser(["text", "json"]),
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
    let manifest_path = matches.get_one::<String>("manifest");
    let interactive = matches.get_flag("interactive");
    let export_file = matches.get_one::<String>("export");
    let generate_suppression = matches.get_one::<String>("generate_suppression");
    let directories: Vec<String> = matches
        .get_many::<String>("directories")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();
    let mut include_paths: Vec<String> = matches
        .get_many::<String>("include_paths")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();
    // A compile database contributes its build's search paths *after* any
    // explicit -I, so a hand-passed path keeps priority in the search order.
    let compile_db = match matches.get_one::<String>("compile_commands") {
        Some(db_path) => {
            let db = analyze::compile_commands::CompileDb::load(std::path::Path::new(db_path))?;
            eprintln!(
                "Loaded compile database: {} {}, {} include paths, {} macro definitions ({})",
                db.entry_count,
                if db.entry_count == 1 {
                    "entry"
                } else {
                    "entries"
                },
                db.include_paths.len(),
                db.defines.len(),
                db_path,
            );
            if !db.forced_includes.is_empty() {
                eprintln!(
                    "  plus {} forced include(s) (/FI), resolved before the headers sources include",
                    db.forced_includes.len(),
                );
            }
            // A compile database stores absolute paths from the machine that
            // built the project. If it was generated elsewhere, those paths are
            // not here, and resolve_includes would silently skip every header
            // rather than fail — an expensive no-op that still looks like it
            // worked. Say so loudly instead.
            let missing = db.missing_include_paths();
            if !missing.is_empty() {
                eprintln!(
                    "Warning: {} of {} compile-database include paths do not exist on this \
                     machine (e.g. {}). If this database was generated on another host or in a \
                     container, its paths need remapping — header resolution will silently skip \
                     them.",
                    missing.len(),
                    db.include_paths.len(),
                    missing[0],
                );
            }
            for p in &db.include_paths {
                if !include_paths.contains(p) {
                    include_paths.push(p.clone());
                }
            }
            Some(db)
        }
        None => None,
    };
    // The compiler's built-in directories go last: they are the lowest-priority
    // half of a real compiler's search order, and anything the user or the
    // build named explicitly should still win.
    if matches.get_flag("system_includes") {
        // A compile database records which compiler built each file, which is
        // the right one to ask. Without one there is nothing to go on but the
        // platform default.
        let compilers: Vec<String> = match &compile_db {
            Some(db) if !db.compilers.is_empty() => db.compilers.clone(),
            _ => vec![analyze::system_includes::DEFAULT_COMPILER.to_string()],
        };
        let sys = analyze::system_includes::query(&compilers);
        let mut added = 0usize;
        for p in &sys.paths {
            if !include_paths.contains(p) {
                include_paths.push(p.clone());
                added += 1;
            }
        }
        eprintln!(
            "System include directories: {} from {} ({})",
            added,
            if sys.queried.len() == 1 {
                "compiler".to_string()
            } else {
                format!("{} compilers", sys.queried.len())
            },
            if sys.queried.is_empty() {
                "none answered".to_string()
            } else {
                sys.queried.join(", ")
            },
        );
        // A compiler that could not be asked is reported rather than swallowed:
        // otherwise a cross-compiler missing from the analysis host looks
        // identical to one that genuinely has no system directories.
        for (compiler, reason) in &sys.failed {
            eprintln!("Warning: could not query '{compiler}' for its system include directories ({reason}); its built-in headers stay out of reach.");
        }
    }
    // Some(path) when the flag was given; the path is empty for the bare
    // flag (summary only) and a file name when the user wants the JSON too.
    let report_macro_gaps: Option<String> = matches.get_one::<String>("report_macro_gaps").cloned();
    let report_deallocator_candidates: Option<String> = matches
        .get_one::<String>("report_deallocator_candidates")
        .cloned();
    if report_deallocator_candidates.is_some() {
        analyze::deallocator_candidates::enable();
    }
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
    // The bounds every unit of work runs under (ADR-0017).
    let nonzero = |v: u64| (v > 0).then_some(v);
    analyze::containment::set_limits(analyze::containment::Limits {
        steps: nonzero(*matches.get_one::<u64>("rule_step_limit").unwrap()),
        time: nonzero(*matches.get_one::<u64>("rule_time_limit").unwrap())
            .map(std::time::Duration::from_secs),
    });
    let detect_relevance = matches.get_flag("detect_relevance");
    let write_manifest = matches.get_one::<String>("write_manifest");

    if matches.get_flag("check_config") {
        // The same parsing, loading and resolution a scan runs, so the two
        // cannot disagree about what is valid. Nothing is scanned. Every
        // command-line flag is read, and the manifest checked against the
        // ones that parsed, so each problem is named once.
        let (settings_cli, mut problems) = parse_settings_from_cli(&matches);
        let checked = load_manifest(manifest_path).and_then(|manifest| {
            resolve_settings(
                &manifest,
                &settings_cli,
                compile_db.as_ref().is_some_and(|db| db.msvc),
            )
        });
        if let Err(e) = checked {
            let text = format!("{e:#}");
            if text.contains("TOML parse error") {
                // A parse error is one problem, however many lines the
                // diagnostic spans.
                problems.push(text.trim().replace('\n', "\n       "));
            } else {
                // The resolver names each problem on a line of its own.
                problems.extend(
                    text.lines()
                        .filter(|l| !l.trim().is_empty())
                        .map(|l| l.trim().to_string()),
                );
            }
        }
        if problems.is_empty() {
            println!("configuration ok");
            return Ok(0);
        }
        for problem in problems {
            eprintln!("error: {problem}");
        }
        return Ok(1);
    }

    let settings_cli = settings_from_cli(&matches)?;

    if let Some(target) = matches.get_one::<String>("write_config") {
        let manifest = load_manifest(manifest_path)?;
        let settings = resolve_settings(
            &manifest,
            &settings_cli,
            compile_db.as_ref().is_some_and(|db| db.msvc),
        )?;
        let text = manifest.render_config(&settings);
        if target == "-" {
            print!("{text}");
        } else {
            let mut file = fs::OpenOptions::new();
            file.write(true);
            if matches.get_flag("overwrite") {
                file.create(true).truncate(true);
            } else {
                file.create_new(true);
            }
            let mut file = file.open(target).map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    anyhow::anyhow!("{target} exists; pass --overwrite to replace it")
                } else {
                    anyhow::anyhow!("cannot write {target}: {e}")
                }
            })?;
            std::io::Write::write_all(&mut file, text.as_bytes())?;
            println!("Wrote configuration to: {target}");
        }
        return Ok(0);
    }

    if let Some(format) = matches.get_one::<String>("list_rules") {
        let manifest = load_manifest(manifest_path)?;
        let registry = aurora_lint::rules::RuleRegistry::new();
        let removed = manifest::removed::removed_rules();
        match format.as_str() {
            "json" => println!(
                "{}",
                serde_json::to_string_pretty(&aurora_lint::rules::listing::render_json(
                    &registry, &manifest, removed
                ))?
            ),
            _ => print!(
                "{}",
                aurora_lint::rules::listing::render_text(&registry, &manifest, removed)
            ),
        }
        return Ok(0);
    }

    if let Some(format) = matches.get_one::<String>("list_options") {
        let settings = resolve_settings(
            &load_manifest(manifest_path)?,
            &settings_cli,
            compile_db.as_ref().is_some_and(|db| db.msvc),
        )?;
        match format.as_str() {
            "json" => println!(
                "{}",
                serde_json::to_string_pretty(&settings::render_json(&settings))?
            ),
            "rst" => print!("{}", settings::render_rst()),
            _ => print!("{}", settings::render_text(&settings)),
        }
        return Ok(0);
    }

    if detect_relevance {
        let mut corpus = vec![path.clone()];
        corpus.extend(directories.iter().cloned());
        let profile = analyze::relevance::detect(&corpus)?;
        println!(
            "Detected: threading={}, windows={}, max_c_standard={:?}",
            profile.has_threading, profile.has_windows, profile.max_c_standard
        );

        let base_manifest = load_manifest(manifest_path)?;
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

    let mut manifest = load_manifest(manifest_path)?;
    if let Some(ref rules) = rule_filter {
        // A removed id would silently cut the scan to nothing.
        let mut ids: Vec<&String> = rules.iter().collect();
        ids.sort();
        for id in ids {
            manifest::removed::warn_if_removed(id, "--rules");
        }
        manifest.restrict_to(rules);
    }
    let mut analysis_settings = resolve_settings(
        &manifest,
        &settings_cli,
        compile_db.as_ref().is_some_and(|db| db.msvc),
    )?;
    let scope = scan_scope(&matches, &manifest);
    analysis_settings.set_prescan_scope(scope.prescan_scope());

    // Handle suppression generation
    if let Some(gen_spec) = generate_suppression {
        handle_generate_suppression(gen_spec)?;
        return Ok(0);
    }

    if interactive {
        #[cfg(feature = "tui")]
        {
            let mut ui = TerminalUI::new(
                path,
                manifest,
                analysis_settings.clone(),
                &directories,
                &include_paths,
            )?;
            ui.run()?;
            return Ok(0);
        }
        #[cfg(not(feature = "tui"))]
        {
            anyhow::bail!(
                "aurora-lint was built without the `tui` feature; rebuild with `cargo build --features tui` to use --interactive"
            );
        }
    }

    println!("Analyzing {} at: {}", project_source.source_type(), path);
    println!(
        "Using manifest: {}",
        manifest_path
            .map(String::as_str)
            .unwrap_or("<built-in default>")
    );

    println!(
        "Settings: {} (policy={}, environment={})",
        analysis_settings
            .matching_preset()
            .map_or_else(|| "custom".to_string(), |p| format!("{p} preset")),
        analysis_settings.policy,
        analysis_settings.environment,
    );

    if diff_only {
        println!("Mode: diff-only (analyzing modified files)");
    }

    // Create progress reporter for CLI
    let progress_reporter = CLIProgressReporter::new(verbosity);

    // Perform analysis with progress reporting
    // The last resort against a hang no checkpoint sees (ADR-0017).
    analyze::containment::start_watchdog();
    let results = analyze_project(
        &project_source,
        &manifest,
        Some(&progress_reporter),
        &directories,
        &include_paths,
        &scope,
        diff_only,
        suppress_file.map(|s| s.as_str()),
        save_prescan.map(|s| s.as_str()),
        load_prescan.map(|s| s.as_str()),
        compile_db.as_ref(),
        jobs,
        report_macro_gaps.is_some(),
        &analysis_settings,
    )?;

    if std::env::var_os("AURORA_LINT_STEP_STATS").is_some() {
        // How far the busiest unit of work is from the step budget
        // (ADR-0017 records the measurement behind the default).
        let (steps, label) = analyze::containment::max_steps_seen();
        eprintln!("step stats: busiest unit of work took {steps} steps: {label}");
    }
    let mut violations = results.violations;
    let suppressed = results.suppressed;
    let macro_gap_report = results.macro_gaps;
    let failures = results.failures;
    let abandoned_rules = results.abandoned_rules;
    let not_converged = results.not_converged;

    // Post-analysis filtering
    if let Some(ref min_sev) = min_severity {
        violations.retain(|v| v.severity >= *min_sev);
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
        export_all_violations(
            &violations,
            &suppressed,
            export_path,
            &analysis_settings,
            export::Incomplete {
                failures: &failures,
                abandoned_rules: &abandoned_rules,
                not_converged: &not_converged,
            },
        )?;
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

    // The macro-gap report goes after the findings so a CI log reads
    // "here is what we found, and here is where we could not look".
    if let (Some(json_path), Some(report)) = (&report_macro_gaps, &macro_gap_report) {
        const ROWS_PER_KIND: usize = 25;
        println!();
        print!("{}", report.render_text(ROWS_PER_KIND));
        if !json_path.is_empty() {
            let json = serde_json::to_string_pretty(report)?;
            fs::write(json_path, json)
                .with_context(|| format!("Failed to write macro-gap report to {json_path}"))?;
            println!(
                "Wrote macro-gap report ({} rows) to: {}",
                report.gaps.len(),
                json_path
            );
        }
    }

    if let Some(json_path) = &report_deallocator_candidates {
        const ROWS: usize = 25;
        let report = analyze::deallocator_candidates::take_report();
        println!();
        print!("{}", report.render_text(ROWS));
        if !json_path.is_empty() {
            let json = serde_json::to_string_pretty(&report)?;
            fs::write(json_path, json).with_context(|| {
                format!("Failed to write deallocator-candidate report to {json_path}")
            })?;
            println!(
                "Wrote deallocator-candidate report ({} rows) to: {}",
                report.candidates.len(),
                json_path
            );
        }
    }

    // Known non-convergence (ADR-0017): not an incomplete scan, but never
    // silent either.
    for (what, n) in &not_converged {
        eprintln!(
            "Warning: {what} did not converge {n} time(s); results there may be incomplete \
             (a known issue, see docs/error-handling.rst)"
        );
    }

    // A crash or a bound (analyze::containment, ADR-0017) leaves every other
    // finding in place, so the output above stands -- but it is incomplete,
    // and that outranks any findings-based verdict: a CI gate must not read a
    // scan with a rule missing as a clean one.
    if !failures.is_empty() || !abandoned_rules.is_empty() {
        for f in &failures {
            eprintln!("Error: {}", f.render());
        }
        for rule in &abandoned_rules {
            eprintln!(
                "Error: rule abandoned: {rule}: failed on {} or more files; none of its \
                 findings are reported",
                analyze::containment::ABANDON_AFTER_FILES
            );
        }
        let rules: std::collections::BTreeSet<_> = failures
            .iter()
            .filter_map(|f| f.rule_id.as_deref())
            .collect();
        let files: std::collections::BTreeSet<_> = failures.iter().map(|f| &f.file).collect();
        eprintln!(
            "Error: scan INCOMPLETE: {} unit(s) of work did not finish in {} file(s){}; the \
             findings above omit what they would have found. A crash is an aurora-lint \
             bug; please report it.",
            failures.len(),
            files.len(),
            if rules.is_empty() {
                String::new()
            } else {
                format!(
                    " (rule{} {})",
                    if rules.len() == 1 { "" } else { "s" },
                    rules.into_iter().collect::<Vec<_>>().join(", ")
                )
            },
        );
        if failures
            .iter()
            .any(|f| f.cause != analyze::containment::Cause::Panic)
        {
            eprintln!(
                "  note: a step or time limit stops work that may only be unusually large; \
                 --rule-step-limit / --rule-time-limit raise them (0 = no limit). See \
                 docs/error-handling.rst."
            );
        }
        return Ok(analyze::containment::EXIT_INCOMPLETE);
    }

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
