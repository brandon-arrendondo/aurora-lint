/// Which storage object a call argument names, in the caller's frame
/// .
pub mod arg_origin;
pub mod argument_objects;
/// Shared AST-based fixed-array-declaration size resolution.
pub mod array_size;
pub mod buffer_size;
pub mod cfg;
/// Assert-style macros that cannot be compiled out (ADR-0011 basis 3), found
/// by what every definition expands to.
pub mod check_macros;
/// Optional `compile_commands.json` ingestion: feeds a build's include search
/// paths and `-D` macro state into the existing prescan/expansion pipeline.
pub mod compile_commands;
pub mod concurrency_roots;
pub mod const_eval;
pub mod containment;
/// Cross-file project context ([`context::ProjectContext`]) gathered by the
/// pre-scan phase and injected into rules that need whole-project data.
pub mod context;
/// Pre-parse repair for a preprocessor guard that falls between a control-flow
/// header (`if`/`while`/`for`) and the body it governs -- `tree-sitter-c`
/// synthesizes an empty consequence, which reads as an unbraced body.
pub mod control_header_preproc_guard;
pub mod dataflow;
/// Preprocessor-dead line ranges under the assumed platform profile, for
/// collectors that must keep one of several same-named conditional
/// definitions.
pub mod dead_regions;
pub mod deallocator_candidates;
pub mod embedded_js_blank;
pub mod empty_macro_blank;
pub mod function_summary;
pub mod has_include_angle;
pub mod include_names;
pub mod init_state;
pub mod input_guard;
/// Pre-parse repair for a label immediately followed by an `#ifdef`/`#if`
/// block -- `tree-sitter-c`'s `labeled_statement` can't parse that shape.
pub mod label_preproc_guard;
pub mod macro_expand;
pub mod macro_gaps;
pub mod macro_semantics;
/// Noreturn-function detection shared by CFG construction.
pub mod noreturn;
pub mod null_state;
pub mod out_param_nonnull;
pub mod paren_preproc_guard;
/// Points-to/alias analysis: resolving an lvalue expression to the set of
/// storage locations it may refer to.
pub mod points_to;
pub mod preproc_arm_choice;
/// Which byte offsets a preprocessor conditional puts in mutually exclusive
/// arms, so a positional lookup does not answer with a record from a branch
/// this position cannot coexist with.
pub mod preproc_arms;
pub mod preproc_dangling_else;
pub mod preproc_split_chain;
/// The pre-scan phase: a first pass over the project (and sibling headers)
/// that builds the [`context::ProjectContext`] later rule passes consume.
pub mod prescan;
pub mod relevance;
/// Per-function mod/ref summaries: what calling a function can write or
/// read, closed over the call graph of the scanned set.
pub mod side_effects;
/// Inline `AURORA-SUPPRESS` comment parsing and suppression-file matching.
pub mod suppression;
/// Recovering the compiler's *implicit* system header directories
/// (`cc -E -Wp,-v -`), which a `compile_commands.json` can never contain.
pub mod system_includes;
pub mod unknown_identifier_recovery;
pub mod value_range;
pub mod vra_access;

use super::files::ProjectSource;
use super::manifest::RuleManifest;
use super::parser::CParser;
use super::progress::ProgressReporter;
use super::rules::{RuleRegistry, RuleViolation};
use suppression::SuppressionManager;

use crate::utility::cert_c::node_children::NodeChildren;
use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A violation that was suppressed by an inline AURORA-SUPPRESS comment.
pub struct SuppressedViolation {
    /// The violation that would have fired without the suppression.
    pub violation: RuleViolation,
    /// The justification text from the suppression comment/file.
    pub justification: String,
}

/// Results from project analysis, containing both active and suppressed violations.
pub struct AnalysisResults {
    /// Violations that were not suppressed.
    pub violations: Vec<RuleViolation>,
    /// Violations suppressed by an inline comment or suppression file.
    pub suppressed: Vec<SuppressedViolation>,
    /// Where the macro-expansion engine was blind during this scan; built
    /// only when `report_macro_gaps` was requested.
    pub macro_gaps: Option<macro_gaps::MacroGapReport>,
    /// Units of work that crashed or ran out of budget (`containment`),
    /// sorted. Non-empty means the findings above are real but incomplete.
    pub failures: Vec<containment::ScanFailure>,
    /// Rules abandoned for the scan after failing on
    /// [`containment::ABANDON_AFTER_FILES`] files; none of their findings are
    /// in `violations` or `suppressed`.
    pub abandoned_rules: Vec<String>,
    /// Analyses known not to converge on some code that stopped short in
    /// this scan, with how often ([`containment::not_converged`]): reported
    /// as warnings, not as an incomplete scan.
    pub not_converged: Vec<(String, u64)>,
}

/// Which files a scan leaves out, as path globs relative to the scanned root
/// (a `-d` directory outside it matches relative to itself). `toolchain.toml`'s
/// `[ignore].paths` count as `report_exclude`, the meaning they always had.
#[derive(Debug, Clone, Default)]
pub struct ScanScope {
    /// Left out of everything: not scanned, not reported, not read by the
    /// prescan.
    pub exclude_all: Vec<String>,
    /// Not scanned or reported, but still read by the prescan.
    pub report_exclude: Vec<String>,
    /// Scanned and reported, but not read by the prescan.
    pub prescan_exclude: Vec<String>,
}

impl ScanScope {
    /// The globs whose files get no findings.
    fn report_globs(&self) -> Vec<String> {
        self.exclude_all
            .iter()
            .chain(&self.report_exclude)
            .cloned()
            .collect()
    }

    /// The globs whose files the prescan does not read.
    fn prescan_globs(&self) -> Vec<String> {
        self.exclude_all
            .iter()
            .chain(&self.prescan_exclude)
            .cloned()
            .collect()
    }

    /// The prescan's scope as both the settings identity and a prescan cache
    /// record it: [`Self::prescan_globs`], sorted and deduplicated. One
    /// function for both, so whatever narrows the prescan also moves the hash.
    pub fn prescan_scope(&self) -> Vec<String> {
        let mut scope = self.prescan_globs();
        scope.sort();
        scope.dedup();
        scope
    }
}

/// Stack for every rayon worker thread: the scan pool built here and, set
/// once at startup by the binary, rayon's global pool. Several analyses
/// recurse once per AST nesting level -- the scan's rules, and on the global
/// pool the cross-file prescan (`function_summary`'s walks) and the macro-gap
/// audit -- and real C reaches thousands of levels, which overflows the
/// 2 MiB a spawned thread gets on Linux and aborts the whole process on input
/// a single-file run, on the 8 MiB main thread, completes.
pub const WORKER_STACK_BYTES: usize = 16 * 1024 * 1024;

/// Run every enabled rule over `project_source`, returning active and
/// suppressed violations. `directories`/`include_paths`/`scope` decide
/// which files are analyzed and which feed the cross-file context; `diff_only` limits analysis to changed files;
/// `save_prescan`/`load_prescan` cache the cross-file pre-scan phase across
/// runs; `jobs` bounds parallelism. `compile_db`, when supplied, contributes
/// the build's `-D` macro state to the cross-file context (its include paths
/// are expected to be already merged into `include_paths` by the caller).
/// `report_macro_gaps` adds a parse-only audit pass that fills
/// `AnalysisResults::macro_gaps`; it never changes a finding.
pub fn analyze_project(
    project_source: &ProjectSource,
    manifest: &RuleManifest,
    progress: Option<&dyn ProgressReporter>,
    directories: &[String],
    include_paths: &[String],
    scope: &ScanScope,
    diff_only: bool,
    suppress_file: Option<&str>,
    save_prescan: Option<&str>,
    load_prescan: Option<&str>,
    compile_db: Option<&compile_commands::CompileDb>,
    jobs: usize,
    report_macro_gaps: bool,
    settings: &crate::settings::AnalysisSettings,
) -> Result<AnalysisResults> {
    let mut violations = Vec::new();
    let mut suppressed = Vec::new();
    let registry = RuleRegistry::new();

    // Pre-compute whether any enabled rule needs VRA (used by prescan + per-file analysis)
    let needs_vra = manifest
        .enabled_rules()
        .any(|(rule_id, _)| registry.get_rule(rule_id).is_some_and(|r| r.needs_vra()));

    // One lookup for the whole scan, so each directory an `#include` search
    // passes through is read once whichever pass asks.
    let header_lookup = include_names::HeaderLookup::new(settings.include_names);

    // A suppression file the tool cannot read in full stops the scan before
    // the prescan spends minutes on a run whose report would be wrong.
    let mut suppression_manager = build_suppression_manager(suppress_file, project_source)?;

    // Declared allocators and deallocators reach the function summaries
    // prescan builds, so they are installed first.
    crate::settings::memory::declare(settings.memory.clone())?;
    // So does a declared closed program, which closes caller sets there.
    crate::settings::closure::declare(settings.flag("closed_program"))?;

    // A fresh count of analyses that stop short (`containment::not_converged`).
    let _ = containment::take_not_converged();

    // Load or compute cross-file context (prescan, includes, optional cache save)
    let mut context = load_project_context(
        project_source,
        progress,
        directories,
        include_paths,
        diff_only,
        save_prescan,
        load_prescan,
        compile_db,
        needs_vra,
        &header_lookup,
        scope,
        settings.facts,
    )?;
    context.settings = std::sync::Arc::new(settings.clone());

    set_project_context_for_enabled(&registry, manifest, &context);

    // The parse-repair pass consults the prescan's macro table to blank a
    // stranded declaration's *macro* rather than its real type or declarator
    // . Built once and shared: parallel mode makes one parser per
    // file.
    let repair_macros = std::sync::Arc::new(
        unknown_identifier_recovery::RepairMacros::from_context(&context),
    );

    warn_unimplemented_rules(manifest, &registry);
    warn_project_wide_switch_offs(
        &registry,
        manifest,
        &context,
        project_source.get_root_path(),
    );

    let c_files = collect_c_files(project_source, diff_only, &scope.report_globs())?;
    let total_files = c_files.len();

    // What did not complete (`containment`, ADR-0017): the prescan's failures
    // first, then the per-file ones. One escalation record per scan, shared
    // by every worker.
    let mut failures = context.prescan_failures.clone();
    let escalation = containment::Escalation::new();

    // A declaration is per scan; a database is per translation unit. Sources
    // the build does not compile are still scanned (ADR-0010 Decision 1) but
    // get their names resolved under a configuration that excludes them, which
    // can leave a name defined only in a ruled-out arm resolving to nothing.
    // Say so rather than let it look like ordinary imprecision; scoping the
    // declaration per TU is an earlier fix.
    if let Some(db) = compile_db {
        let uncovered = db.uncovered_sources(&c_files);
        if !uncovered.is_empty() && !db.declared_macro_state().is_empty() {
            eprintln!(
                "Warning: {} of {} scanned .c files are not compiled by the database's \
                 configuration (e.g. {}). They are still analysed, but their conditional \
                 definitions resolve under a configuration that excludes them, so a macro \
                 defined only in an arm that configuration rules out will not resolve at all.",
                uncovered.len(),
                c_files.iter().filter(|p| p.ends_with(".c")).count(),
                uncovered[0],
            );
        }
    }

    // Independent of the rules: it reads the same files and context, so it
    // can run first and the findings loop below stays untouched.
    let macro_gaps = report_macro_gaps.then(|| {
        macro_gaps::build_report(
            &c_files,
            &context,
            directories,
            include_paths,
            &header_lookup,
        )
    });

    // Determine effective parallelism
    let effective_jobs = if jobs == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        jobs
    };

    if effective_jobs > 1 && total_files > 1 {
        // Parallel analysis with rayon — per-file parser and rule registry.
        // Worker threads get WORKER_STACK_BYTES, not the 2 MiB default.
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(effective_jobs)
            .stack_size(WORKER_STACK_BYTES)
            .build()?;
        let file_counter = AtomicUsize::new(0);

        let results: Vec<_> = pool.install(|| {
            c_files
                .iter()
                .par_bridge()
                .map(|file_path| {
                    if let Some(reporter) = progress {
                        if reporter.is_cancelled() {
                            return (Vec::new(), Vec::new(), Vec::new());
                        }
                    }

                    // Not source text, or too large: skipped and reported,
                    // never parsed (ADR-0017).
                    if let Err(refusal) = input_guard::admit(std::path::Path::new(file_path)) {
                        let failure = containment::ScanFailure::refused(file_path, &refusal);
                        return (Vec::new(), Vec::new(), vec![failure]);
                    }
                    let _permit = input_guard::large_file_permit(std::path::Path::new(file_path));
                    let mut parser = match CParser::new() {
                        Ok(p) => p,
                        Err(_) => return (Vec::new(), Vec::new(), Vec::new()),
                    };
                    parser.set_repair_macros(std::sync::Arc::clone(&repair_macros));
                    let file_registry = RuleRegistry::new();
                    // The context this file may use, which is the shared one
                    // unless the file defines a name some other file also
                    // defines `static`.
                    let local = context.as_seen_from(std::path::Path::new(file_path));
                    let file_context = local.as_ref().unwrap_or(&context);
                    set_project_context_for_enabled(&file_registry, manifest, file_context);
                    let mut file_supp = suppression_manager.clone();

                    let result = analyze_one_file_contained(
                        file_path,
                        &mut parser,
                        &file_registry,
                        manifest,
                        file_context,
                        needs_vra,
                        &mut file_supp,
                        &escalation,
                        None,
                        0,
                        total_files,
                        false,
                    );

                    let completed = file_counter.fetch_add(1, Ordering::Relaxed) + 1;
                    if let Some(reporter) = progress {
                        reporter.report_file(completed, total_files, file_path, "");
                    }

                    result
                })
                .collect()
        });

        for (v, s, f) in results {
            violations.extend(v);
            suppressed.extend(s);
            failures.extend(f);
        }

        let abandoned_rules =
            withhold_abandoned(&escalation, &mut violations, &mut suppressed, &mut failures);
        sort_for_deterministic_output(&mut violations, &mut suppressed);
        failures.sort();
        failures.dedup();

        if let Some(reporter) = progress {
            reporter.report_complete(violations.len());
        }

        return Ok(AnalysisResults {
            violations,
            suppressed,
            macro_gaps,
            failures,
            abandoned_rules,
            not_converged: containment::take_not_converged(),
        });
    }

    // Sequential analysis (single-threaded)
    // Fresh registry per file to prevent cross-file state leakage from RefCell fields
    let mut parser = CParser::new()?;
    parser.set_repair_macros(std::sync::Arc::clone(&repair_macros));

    for (file_idx, file_path) in c_files.iter().enumerate() {
        // Check for cancellation before processing each file
        if let Some(reporter) = progress {
            if reporter.is_cancelled() {
                // Return partial results collected so far
                break;
            }
        }

        if let Err(refusal) = input_guard::admit(std::path::Path::new(file_path)) {
            failures.push(containment::ScanFailure::refused(file_path, &refusal));
            continue;
        }

        // Create fresh rule instances per file (matches parallel mode behavior)
        let file_registry = RuleRegistry::new();
        let local = context.as_seen_from(std::path::Path::new(file_path));
        let file_context = local.as_ref().unwrap_or(&context);
        set_project_context_for_enabled(&file_registry, manifest, file_context);

        let (file_violations, file_suppressed, file_failures) = analyze_one_file_contained(
            file_path,
            &mut parser,
            &file_registry,
            manifest,
            file_context,
            needs_vra,
            &mut suppression_manager,
            &escalation,
            progress,
            file_idx,
            total_files,
            true,
        );
        violations.extend(file_violations);
        suppressed.extend(file_suppressed);
        if file_failures
            .iter()
            .any(|f| f.stage == containment::Stage::File)
        {
            // A panic outside any rule may have left the parser mid-file.
            parser = CParser::new()?;
            parser.set_repair_macros(std::sync::Arc::clone(&repair_macros));
        }
        failures.extend(file_failures);
    }

    let abandoned_rules =
        withhold_abandoned(&escalation, &mut violations, &mut suppressed, &mut failures);
    sort_for_deterministic_output(&mut violations, &mut suppressed);
    failures.sort();
    failures.dedup();

    // Report completion
    if let Some(reporter) = progress {
        reporter.report_complete(violations.len());
    }

    Ok(AnalysisResults {
        violations,
        suppressed,
        macro_gaps,
        failures,
        abandoned_rules,
        not_converged: containment::take_not_converged(),
    })
}

/// Drop every finding of a rule the scan abandoned (`containment`), active
/// and suppressed alike, and return those rules. All of them, not only the
/// ones after the decision, so parallel scheduling cannot change the output.
///
/// The abandoned rule's per-file failures go too: which of its files were
/// reached before the decision depends on scheduling, so the one
/// "abandoned" entry stands for them, and the reported set is the same on
/// every run. MEM31-C's deallocator-candidate rows are part of its output
/// and are withheld with it.
fn withhold_abandoned(
    escalation: &containment::Escalation,
    violations: &mut Vec<RuleViolation>,
    suppressed: &mut Vec<SuppressedViolation>,
    failures: &mut Vec<containment::ScanFailure>,
) -> Vec<String> {
    let abandoned = escalation.abandoned_rules();
    if !abandoned.is_empty() {
        violations.retain(|v| !abandoned.contains(&v.rule_id));
        suppressed.retain(|s| !abandoned.contains(&s.violation.rule_id));
        failures.retain(|f| {
            f.rule_id
                .as_ref()
                .is_none_or(|rule| !abandoned.contains(rule))
        });
        if abandoned.iter().any(|r| r == "MEM31-C") {
            deallocator_candidates::discard_all();
        }
    }
    abandoned
}

/// Load or compute the cross-file project context: prescan cache, directory
/// prescan or sibling-header scan, #include resolution, and optional cache save.
#[allow(clippy::too_many_arguments)]
fn load_project_context(
    project_source: &ProjectSource,
    progress: Option<&dyn ProgressReporter>,
    directories: &[String],
    include_paths: &[String],
    diff_only: bool,
    save_prescan: Option<&str>,
    load_prescan: Option<&str>,
    compile_db: Option<&compile_commands::CompileDb>,
    needs_vra: bool,
    header_lookup: &include_names::HeaderLookup,
    scope: &ScanScope,
    data_model: crate::settings::IntFacts,
) -> Result<context::ProjectContext> {
    // The globs the prescan leaves out, as a cache records them, and the
    // ignore built from exactly those: a context built without them holds
    // other definitions. toolchain.toml's ignores are report-only.
    let prescan_scope = scope.prescan_scope();
    let prescan_scope_key = if prescan_scope.is_empty() {
        String::new()
    } else {
        serde_json::to_string(&prescan_scope)?
    };
    let prescan_ignore = path_ignore(prescan_scope)?;
    let root = project_source.get_root_path().to_string();
    let scoped_out = |path: &std::path::Path, base: &str| {
        prescan::is_scoped_out(&prescan_ignore, &root, base, path)
    };
    // A declared build configuration decides which conditional definitions the
    // collectors below may keep, so it has to be in force BEFORE prescan runs
    // -- unlike the `-D` macro *values*, which are folded in at the end because
    // real source must win over a build flag. Same database, two questions, two
    // orderings: see `dead_regions::declare_scan_profile`. A context restored
    // with --load-prescan was built under whatever profile the saving run
    // declared; the declaration here still governs the per-file collection the
    // rules do, which is the same split --load-prescan already lives with.
    if let Some(db) = compile_db {
        let declared = db.declared_macro_state();
        if !declared.is_empty() {
            dead_regions::declare_scan_profile(declared).map_err(|e| anyhow::anyhow!(e))?;
        }
    }

    // The settings the facts collected below depend on: a cache records them
    // and is refused under different ones. `prescan_scope` is always supplied,
    // "" when the prescan leaves nothing out, since only the keys given here
    // are compared: a cache built leaving files out must be refused by a run
    // that leaves nothing out, and the reverse. A glob may hold a comma, so
    // the list is encoded as JSON.
    let built_under = std::collections::BTreeMap::from([
        (
            "include_names".to_string(),
            header_lookup.mode().to_string(),
        ),
        ("prescan_scope".to_string(), prescan_scope_key),
        // The limit macros and sizeof the macro constants are resolved with:
        // every integer fact, not a data model's name, since a project may override
        // any of them. No implicit value is registered, so a cache built when
        // the data model alone decided them is refused rather than guessed.
        ("int_facts".to_string(), data_model.fingerprint()),
        // A declared closed program closes caller sets, which the caller-set
        // proofs aggregated into the summaries read.
        (
            "closed_program".to_string(),
            crate::settings::closure::declared().to_string(),
        ),
    ]);

    let mut context = if let Some(cache_path) = load_prescan {
        let path = std::path::Path::new(cache_path);
        if path.exists() {
            if let Some(reporter) = progress {
                reporter.report_prescan_start(0);
            }
            let ctx = context::ProjectContext::load_from_file(path)?;
            ctx.check_built_under(&built_under, path)?;
            let declared = crate::settings::memory::declared();
            if ctx.memory_declarations != *declared {
                anyhow::bail!(
                    "prescan cache {} was built under allocator/deallocator declarations \
                     {:?}, and this run declares {:?}; re-create it with --save-prescan",
                    cache_path,
                    ctx.memory_declarations,
                    declared
                );
            }
            if let Some(reporter) = progress {
                reporter.report_prescan_complete(ctx.known_functions.len());
            }
            ctx
        } else {
            anyhow::bail!("Prescan cache file not found: {}", cache_path);
        }
    } else if directories.is_empty() {
        // No -d: the target is its own context. Prescan the scan set itself
        // (every C file in the target, not the --diff subset -- unmodified
        // files are exactly the context a diff needs) as if `-d <target>`
        // had been given, so a first-touch `aurora-lint foo.c` has seen the
        // definitions in the file it is about to analyse. Before this, a
        // single-file target got only its sibling headers' declarations and
        // a directory target nothing at all, producing findings that
        // vanished the moment the same directory was named with -d. -d remains
        // the way to add context from OUTSIDE the target.
        let mut files: Vec<std::path::PathBuf> = project_source
            .get_c_files()?
            .into_iter()
            .map(std::path::PathBuf::from)
            .collect();
        if let Some(dir) = project_source.prescan_dir() {
            files.extend(prescan::sibling_headers(&dir));
        }
        files.retain(|f| !scoped_out(f, &root));
        prescan::prescan_files(files, progress, needs_vra, data_model)?
    } else {
        prescan::prescan_directories(directories, progress, needs_vra, &scoped_out, data_model)?
    };

    // Stamp only a context built here. A loaded one keeps the record it was
    // saved with (already checked above), so re-saving it never claims
    // settings it was not built under.
    if load_prescan.is_none() {
        context.built_under = built_under;
    }

    // Resolve #include directives against include search paths, and the
    // build's forced includes, which need resolving even with no search path.
    let forced_includes: &[String] = compile_db.map_or(&[], |db| &db.forced_includes);
    if !include_paths.is_empty() || !forced_includes.is_empty() {
        let mut c_files = if diff_only {
            project_source.get_modified_c_files()?
        } else {
            project_source.get_c_files()?
        };
        // A file the scope leaves out of the prescan is no includer either:
        // resolving its #includes would fold in the headers only it reads,
        // and their definitions would stand for the functions other files
        // call. A header an in-scope file includes is still read.
        c_files.retain(|f| !scoped_out(std::path::Path::new(f), &root));
        // The project is the tree being scanned plus any -d directory: a
        // search root outside it cannot make an unresolvable include a
        // *project* header.
        let mut project_roots: Vec<String> = vec![project_source.get_root_path().to_string()];
        project_roots.extend(directories.iter().cloned());
        prescan::resolve_includes(
            &c_files,
            forced_includes,
            include_paths,
            &project_roots,
            &mut context,
            progress,
            needs_vra,
            data_model,
            header_lookup,
        )?;
    }

    // Fold in the build's `-D` macro state last, so that any macro the real
    // source already defined wins over a command-line flag of the same name
    // (see `compile_commands`' gap-filling invariant). Runs before the cache
    // save so a saved prescan carries the same context a live run would build.
    if let Some(db) = compile_db {
        db.merge_defines_into(&mut context, data_model)?;
    }

    // Every alias is known now: keep only the call counts that can rule one
    // out (`ProjectContext::as_seen_from`).
    context.retain_alias_call_arities();

    // Save prescan cache if requested (after prescan + include resolution).
    // Not when the prescan is incomplete: a later scan loading the cache
    // would inherit the missing facts without knowing (ADR-0017). This scan
    // reports the failures and exits 3; the cache simply does not exist.
    if let Some(cache_path) = save_prescan.filter(|_| !context.prescan_failures.is_empty()) {
        eprintln!(
            "Warning: not saving the prescan cache to {cache_path}: the prescan of {} file(s) \
             did not complete",
            context.prescan_failures.len()
        );
    } else if let Some(cache_path) = save_prescan {
        context.save_to_file(std::path::Path::new(cache_path))?;
        eprintln!(
            "Saved prescan cache ({} functions, {} summaries) to: {}",
            context.known_functions.len(),
            context.function_summaries.len(),
            cache_path,
        );
    }

    Ok(context)
}

/// Hand the cross-file context to the rules this scan will actually run.
///
/// Every file gets a fresh registry (see the per-file loops above), and most
/// rules take the context by deep-copying the parts they read -- function
/// summaries, macro tables, an inverted call graph -- into their own cells.
/// Offering it to all ~300 registered rules made that copy the dominant cost
/// of a scan: on a Juliet CWE directory it outweighed parsing, CFG/VRA and
/// the enabled rules' own checks combined by an order of magnitude, and it
/// grew with every rule that learned to read a new context table. Only a
/// rule the manifest enables is ever asked to check a file, so only those
/// receive the context.
///
/// The settings go to every enabled rule unconditionally; the context only
/// when the pre-scan found cross-file data, since some rules read "a context
/// was set" as "the project's function set is known".
fn set_project_context_for_enabled(
    registry: &RuleRegistry,
    manifest: &RuleManifest,
    context: &context::ProjectContext,
) {
    let has_cross_file_data = context.has_cross_file_data();
    for (rule_id, _) in manifest.enabled_rules() {
        if let Some(rule) = registry.get_rule(rule_id) {
            rule.set_analysis_settings(&context.settings);
            if has_cross_file_data {
                rule.set_project_context(context);
            }
        }
    }
}

/// Name each enabled rule that stands down for the whole project, with the
/// project and the reason. A rule only sees the context when the prescan
/// found cross-file data (`set_project_context_for_enabled`), so only then
/// can it have switched itself off.
fn warn_project_wide_switch_offs(
    registry: &RuleRegistry,
    manifest: &RuleManifest,
    context: &context::ProjectContext,
    project: &str,
) {
    if !context.has_cross_file_data() {
        return;
    }
    for (rule_id, _) in manifest.enabled_rules() {
        if let Some(reason) = registry
            .get_rule(rule_id)
            .and_then(|rule| rule.project_wide_switch_off(context))
        {
            eprintln!("Warning: {rule_id} in {project}: {reason}");
        }
    }
}

/// Warn about rules that are enabled in the manifest but have no implementation.
fn warn_unimplemented_rules(manifest: &RuleManifest, registry: &RuleRegistry) {
    let mut unimplemented_rules = Vec::new();
    for (rule_id, _) in manifest.enabled_rules() {
        if registry.get_rule(rule_id).is_none() {
            unimplemented_rules.push(rule_id.clone());
        }
    }

    if !unimplemented_rules.is_empty() {
        eprintln!("Warning: The following rules are enabled in manifest but not implemented:");
        for rule_id in &unimplemented_rules {
            eprintln!("  - {}", rule_id);
        }
        eprintln!("These rules will be skipped during analysis.\n");
    }
}

/// Collect the C files to analyze: gather (all or modified), drop ignored
/// matches (`toolchain.toml` `[ignore].paths` plus `excludes`, the globs
/// whose files get no findings), then sort by size descending for LPT
/// scheduling.
fn collect_c_files(
    project_source: &ProjectSource,
    diff_only: bool,
    excludes: &[String],
) -> Result<Vec<String>> {
    let mut c_files = if diff_only {
        project_source.get_modified_c_files()?
    } else {
        project_source.get_c_files()?
    };

    // Drop files matching a project-wide `toolchain.toml` ignore or an
    // --exclude/--report-exclude path glob (e.g. checked-in amalgamations or
    // test harnesses). Whether they still feed the cross-file prescan is the
    // scope's other half (`ScanScope::prescan_globs`).
    let ignore = build_path_ignore(project_source, excludes)?;
    let root = project_source.get_root_path();
    let before = c_files.len();
    c_files.retain(|f| !ignore.is_ignored(std::path::Path::new(&relative_to_root(f, root))));
    let removed = before - c_files.len();
    if removed > 0 {
        eprintln!("Excluded {} file(s) matching ignore patterns", removed);
    }

    // LPT scheduling: sort files by size descending so largest files are dispatched first.
    // Combined with par_bridge() demand-driven dispatch, this implements Graham's LPT
    // algorithm (1969) for makespan minimization — (4/3 - 1/3m) approximation ratio.
    c_files
        .sort_by_cached_key(|f| std::cmp::Reverse(fs::metadata(f).map(|m| m.len()).unwrap_or(0)));

    Ok(c_files)
}

/// Builds the combined ignore matcher from `toolchain.toml`'s shared
/// `[ignore].paths` (discovered by walking up from the project root) and the
/// CLI's report-excluding globs, so a project's file/directory ignores can be
/// expressed once instead of only via the command line on every invocation.
fn build_path_ignore(
    project_source: &ProjectSource,
    excludes: &[String],
) -> Result<lang_parsing_substrate::PathIgnore> {
    let mut patterns: Vec<String> = Vec::new();
    let root = std::path::Path::new(project_source.get_root_path());
    if let Some(toolchain) = crate::toolchain::ToolchainConfig::discover(root)? {
        patterns.extend(toolchain.ignore.paths);
    }
    patterns.extend(excludes.iter().cloned());
    path_ignore(patterns)
}

/// The ignore matcher for `patterns`, skipping (with a warning) any that is
/// not a valid glob.
fn path_ignore(patterns: Vec<String>) -> Result<lang_parsing_substrate::PathIgnore> {
    // Validate patterns individually so one bad glob doesn't discard every
    // other ignore pattern (toolchain.toml's included).
    let valid: Vec<String> = patterns
        .into_iter()
        .filter(|p| {
            let ok = lang_parsing_substrate::PathIgnore::new([p.as_str()]).is_ok();
            if !ok {
                eprintln!("Warning: invalid ignore glob '{}'", p);
            }
            ok
        })
        .collect();

    lang_parsing_substrate::PathIgnore::new(&valid)
        .map_err(|e| anyhow::anyhow!("Invalid ignore glob pattern: {e}"))
}

/// Strips `root` (and a leading path separator) from `path`, and normalizes
/// to `/` separators, so a pattern like `"vendor/**"` in `toolchain.toml`
/// matches regardless of whether the project was opened with an absolute or
/// relative path — glob patterns anchor to the start of the matched string.
fn relative_to_root(path: &str, root: &str) -> String {
    let normalized = path.replace('\\', "/");
    let root_normalized = root.replace('\\', "/");
    normalized
        .strip_prefix(&root_normalized)
        .map(|s| s.trim_start_matches('/').to_string())
        .unwrap_or(normalized)
}

/// Build a suppression manager, loading the TOML suppression file if provided
/// or auto-detected at `<root>/suppress.toml` — the shared, all-tools file
/// from `lang_parsing_substrate/docs/unified-config-spec.md` — falling back
/// to the legacy `<root>/.aurora-lint-suppress.toml` and `<root>/.sqc-suppress.toml`
/// names if `suppress.toml` isn't present (all are parsed with the same
/// `[[suppress]]` schema).
fn build_suppression_manager(
    suppress_file: Option<&str>,
    project_source: &ProjectSource,
) -> Result<SuppressionManager> {
    let mut suppression_manager = SuppressionManager::new();

    let toml_path = suppress_file.map(String::from).or_else(|| {
        let root = std::path::Path::new(project_source.get_root_path());
        [
            root.join("suppress.toml"),
            root.join(".aurora-lint-suppress.toml"),
            root.join(".sqc-suppress.toml"),
        ]
        .into_iter()
        .find(|p| p.exists())
        .and_then(|p| p.to_str().map(String::from))
    });
    if let Some(ref path) = toml_path {
        match suppression_manager.load_from_toml(path) {
            Ok(count) => {
                let wc = suppression_manager.wildcard_count();
                if wc > 0 {
                    eprintln!(
                        "Loaded {} suppressions ({} wildcard) from {}",
                        count, wc, path
                    );
                } else {
                    eprintln!("Loaded {} suppressions from {}", count, path);
                }
            }
            Err(e) => anyhow::bail!(e),
        }
    }

    Ok(suppression_manager)
}

/// Total order on violations, so two runs of one binary over one tree
/// export byte-identical files. `(file, line, column, rule_id)` alone is
/// not total: a rule that reports two messages at one site, or emits the
/// same finding twice, leaves those records in whatever order the worker
/// threads finished, and a `cmp` of two exports fails on every pair of
/// runs even when nothing changed. Records equal on every field
/// here are indistinguishable in any export, so their relative order does
/// not matter.
fn violation_order(a: &RuleViolation, b: &RuleViolation) -> std::cmp::Ordering {
    a.file_path
        .cmp(&b.file_path)
        .then(a.line.cmp(&b.line))
        .then(a.column.cmp(&b.column))
        .then(a.rule_id.cmp(&b.rule_id))
        .then(a.message.cmp(&b.message))
        .then(a.suggestion.cmp(&b.suggestion))
        .then(a.requires_manual_review.cmp(&b.requires_manual_review))
}

/// Order both result vectors by [`violation_order`]. Called on the
/// sequential path as well as the parallel one, so `-j 1` and `-j N`
/// produce the same bytes, and on `suppressed` too, since SARIF exports
/// it alongside the active findings.
fn sort_for_deterministic_output(
    violations: &mut [RuleViolation],
    suppressed: &mut [SuppressedViolation],
) {
    violations.sort_by(violation_order);
    suppressed.sort_by(|a, b| {
        violation_order(&a.violation, &b.violation).then(a.justification.cmp(&b.justification))
    });
}

/// Parse and run all enabled rules over a single file, partitioning findings
/// into active and suppressed. Shared by the parallel and sequential drivers.
///
/// When `per_rule_progress` is set (sequential mode), cancellation is checked
/// and progress reported before each rule; parallel mode reports once per file
/// in the caller instead.
#[allow(clippy::too_many_arguments)]
fn analyze_one_file(
    file_path: &str,
    parser: &mut CParser,
    file_registry: &RuleRegistry,
    manifest: &RuleManifest,
    context: &context::ProjectContext,
    needs_vra: bool,
    suppression_manager: &mut SuppressionManager,
    escalation: &containment::Escalation,
    progress: Option<&dyn ProgressReporter>,
    file_idx: usize,
    total_files: usize,
    per_rule_progress: bool,
) -> (
    Vec<RuleViolation>,
    Vec<SuppressedViolation>,
    Vec<containment::ScanFailure>,
) {
    let mut file_violations = Vec::new();
    let mut file_suppressed = Vec::new();
    let mut file_failures = Vec::new();

    let parsed = match parser.parse_file(file_path) {
        Ok(parsed) => Some(parsed),
        Err(e) => {
            // A file the directory walk listed but the parser would not
            // take -- a binary blob with a C extension, an
            // unreadable path. Say so once here, at the one place each
            // file is scanned; silently producing nothing for it is how a
            // whole file used to vanish from a run unnoticed.
            eprintln!("Warning: {}: {}", file_path, e.root_cause());
            None
        }
    };
    if let Some((tree, source)) = parsed {
        // A `.h` file is ambiguous between C and C++ by extension alone; a
        // header written entirely in C++ (a vendored C++ wrapper API
        // shipped alongside a C library, e.g. mosquitto's
        // libmosquittopp.h) parses under tree-sitter-c anyway, producing
        // ERROR-node garbage that several independent C-oriented rules
        // (DCL15-C, DCL19-C, DCL20-C, MSC13-C, WIN04-C, API02-C, EXP37-C)
        // have each misread as real C declarations. Detect and
        // skip such files entirely rather than analyzing nonsense --
        // tools_sqc is CERT-C only, so a file that can only be C++ is out
        // of scope, not a source of findings.
        if file_path.ends_with(".h") && lang_parsing_substrate::looks_like_cpp(source.as_bytes()) {
            return (file_violations, file_suppressed, file_failures);
        }

        let root_node = tree.root_node();

        // CFGs for every function definition in this file, plus VRA if any
        // enabled rule needs it. The generated fixture tests build their state
        // through this same call (this repo).
        let analysis = build_file_analysis(
            std::path::Path::new(file_path),
            &root_node,
            &source,
            context,
            needs_vra,
        );

        // Extract suppressions from the current file
        suppression_manager.extract_from_source(file_path, &source);

        for (rule_id, rule_config) in manifest.enabled_rules() {
            // Sequential mode: check cancellation and report progress per rule
            if per_rule_progress {
                if let Some(reporter) = progress {
                    if reporter.is_cancelled() {
                        break;
                    }
                    reporter.report_file(file_idx + 1, total_files, file_path, rule_id);
                }
            }

            // Check if rule is implemented
            if let Some(rule) = file_registry.get_rule(rule_id) {
                // Skip rules that don't apply to this file type (e.g. header-only rules)
                if !rule.applies_to_file(file_path) {
                    continue;
                }
                // Provide CFGs for flow-sensitive rules (e.g. EXP34-C) and
                // VRA results for integer-range-sensitive ones.
                // A rule that has failed on enough files is abandoned for
                // the scan (`containment::Escalation`).
                if escalation.abandoned(rule_id) {
                    continue;
                }
                analysis.apply_to(rule);
                // A crash or a runaway in one rule costs that rule's findings
                // for this file, not the scan (`containment`, ADR-0017).
                let rollback = deallocator_candidates::pending_len();
                let label = format!("{rule_id} on {file_path}");
                let mut rule_violations = match containment::contain(&label, || {
                    test_failure_hook(rule_id);
                    rule.check(&root_node, &source)
                }) {
                    Ok(found) => found,
                    Err(failure) => {
                        deallocator_candidates::truncate_pending(rollback);
                        escalation.record(rule_id, file_path);
                        file_failures.push(containment::ScanFailure::new(
                            containment::Stage::Rule,
                            file_path,
                            Some(rule_id),
                            failure,
                        ));
                        continue;
                    }
                };

                // Set file path and severity on all violations
                for v in &mut rule_violations {
                    v.file_path = file_path.to_string();
                    v.severity = rule_config
                        .severity
                        .clone()
                        .unwrap_or_else(|| rule.severity());
                }

                // Partition into active and suppressed violations
                for v in rule_violations {
                    if let Some(j) = suppression_manager
                        .should_suppress(file_path, rule_id, v.line, &source, &v.message)
                    {
                        file_suppressed.push(SuppressedViolation {
                            justification: j.to_string(),
                            violation: v,
                        });
                    } else {
                        file_violations.push(v);
                    }
                }
            }
        }
        deallocator_candidates::flush_file(file_path);
    }

    (file_violations, file_suppressed, file_failures)
}

/// [`analyze_one_file`], with a panic outside any one rule's check (reading,
/// parsing, building the file's CFGs and value ranges) contained to the file:
/// it then contributes no findings and one [`containment::Stage::File`]
/// failure.
#[allow(clippy::too_many_arguments)]
fn analyze_one_file_contained(
    file_path: &str,
    parser: &mut CParser,
    file_registry: &RuleRegistry,
    manifest: &RuleManifest,
    context: &context::ProjectContext,
    needs_vra: bool,
    suppression_manager: &mut SuppressionManager,
    escalation: &containment::Escalation,
    progress: Option<&dyn ProgressReporter>,
    file_idx: usize,
    total_files: usize,
    per_rule_progress: bool,
) -> (
    Vec<RuleViolation>,
    Vec<SuppressedViolation>,
    Vec<containment::ScanFailure>,
) {
    let rollback = deallocator_candidates::pending_len();
    containment::contain(file_path, || {
        analyze_one_file(
            file_path,
            parser,
            file_registry,
            manifest,
            context,
            needs_vra,
            suppression_manager,
            escalation,
            progress,
            file_idx,
            total_files,
            per_rule_progress,
        )
    })
    .unwrap_or_else(|failure| {
        deallocator_candidates::truncate_pending(rollback);
        let failure =
            containment::ScanFailure::new(containment::Stage::File, file_path, None, failure);
        (Vec::new(), Vec::new(), vec![failure])
    })
}

/// Test hook, debug builds only: `AURORA_LINT_TEST_FAIL=RULE:panic` makes
/// RULE's check panic, and `RULE:spin` makes it loop through checkpoints
/// until its step budget stops it; `prescan:panic` does the same to each
/// file's prescan. How the CLI tests exercise containment without a buggy
/// rule to hand.
#[cfg(debug_assertions)]
pub(crate) fn test_failure_hook(rule_id: &str) {
    let Ok(spec) = std::env::var("AURORA_LINT_TEST_FAIL") else {
        return;
    };
    for item in spec.split(',') {
        match item.split_once(':') {
            Some((rule, "panic")) if rule == rule_id => {
                panic!("AURORA_LINT_TEST_FAIL panic in {rule_id}")
            }
            Some((rule, "spin")) if rule == rule_id => loop {
                containment::checkpoint();
            },
            _ => {}
        }
    }
}

#[cfg(not(debug_assertions))]
#[inline(always)]
pub(crate) fn test_failure_hook(_rule_id: &str) {}

/// Print a suppression-comment snippet for `spec` (`FILE:LINE:RULE`), for a
/// user to paste inline rather than hand-writing the comment syntax.
pub fn handle_generate_suppression(spec: &str) -> Result<()> {
    // Parse the specification: FILE:LINE:RULE
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    if parts.len() != 3 {
        eprintln!("Error: Invalid format. Use FILE:LINE:RULE");
        eprintln!("Example: src/main.c:42:ARR30-C");
        return Ok(());
    }

    let file_path = parts[0];
    let rule_id = parts[2];

    let line: usize = match parts[1].parse() {
        Ok(n) if n > 0 => n,
        _ => {
            eprintln!("Error: Invalid line number");
            return Ok(());
        }
    };

    // Read the source file
    let source = match fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Error: Cannot read file '{}': {}", file_path, e);
            return Ok(());
        }
    };

    let lines: Vec<&str> = source.lines().collect();
    if line > lines.len() {
        eprintln!(
            "Error: Line {} exceeds file length ({} lines)",
            line,
            lines.len()
        );
        return Ok(());
    }

    // Get the code line, stripping any existing suppress comment (either
    // spelling) so the hash covers only the code portion.
    let raw_line = lines[line - 1];
    let code = [
        "// AURORA-SUPPRESS",
        "/* AURORA-SUPPRESS",
        "// SQC-SUPPRESS",
        "/* SQC-SUPPRESS",
    ]
    .iter()
    .filter_map(|opener| raw_line.find(opener))
    .min()
    .map_or(raw_line, |pos| &raw_line[..pos]);

    let hash = SuppressionManager::calculate_suppression_hash(rule_id, code);

    println!(
        "Generated suppression for {}:{}:{}",
        file_path, line, rule_id
    );
    println!();
    println!("Code:");
    println!("{:4}: {}", line, raw_line);
    println!();
    let filename = std::path::Path::new(file_path)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(file_path);

    println!("Add on the line before (standalone comment):");
    println!(
        "// tools:suppress aurora-lint:{} HASH:{} JUSTIFICATION:\"TODO: Add justification\"",
        rule_id, hash
    );
    println!();
    println!("Native form (also accepted; standalone or inline):");
    println!(
        "// AURORA-SUPPRESS: {} HASH:{} JUSTIFICATION: \"TODO: Add justification\"",
        rule_id, hash
    );
    println!();
    println!("Or add to suppress.toml (for read-only codebases):");
    println!("[[suppress]]");
    println!("name = \"TODO-unique-name\"");
    println!("tool = \"aurora-lint\"");
    println!("file = \"{}\"", filename);
    println!("rule = \"{}\"", rule_id);
    println!("hash = \"{}\"", hash);
    println!("justification = \"TODO: Add justification\"");

    Ok(())
}

/// The per-file analysis state a scan hands to every rule: control-flow graphs
/// for each function definition, plus value ranges when some enabled rule asks
/// for them.
///
/// Both `analyze_one_file` and the fixture tests `build.rs` generates go
/// through [`build_file_analysis`] and [`FileAnalysis::apply_to`], so a rule
/// can never be exercised in tests under a context the shipped scan does not
/// build (this repo).
pub(crate) struct FileAnalysis {
    pub(crate) function_cfgs: HashMap<usize, cfg::FunctionCfg>,
    pub(crate) vra_results: HashMap<usize, value_range::RangeAnalysisResult>,
    pub(crate) visible_types: context::VisibleTypes,
    pub(crate) file_path: std::path::PathBuf,
}

impl FileAnalysis {
    /// Hand this file's state to `rule` the way a scan does -- VRA only when
    /// there is any, matching the shipped gate.
    pub(crate) fn apply_to<R: crate::rules::CertRule + ?Sized>(&self, rule: &R) {
        rule.set_function_cfgs(&self.function_cfgs);
        rule.set_visible_types(&self.visible_types);
        rule.set_file_path(&self.file_path);
        if !self.vra_results.is_empty() {
            rule.set_vra_results(&self.vra_results);
        }
    }
}

/// Build the per-file analysis state for one already-parsed file.
pub(crate) fn build_file_analysis(
    file_path: &std::path::Path,
    root_node: &tree_sitter::Node,
    source: &str,
    context: &context::ProjectContext,
    needs_vra: bool,
) -> FileAnalysis {
    let mut function_cfgs: HashMap<usize, cfg::FunctionCfg> = HashMap::new();
    collect_function_cfgs(root_node, source, &mut function_cfgs, &context.settings);

    let vra_results = compute_vra_if_needed(
        needs_vra,
        &function_cfgs,
        root_node,
        source,
        &context.function_summaries,
        &context.macro_constants,
        context.settings.facts,
    );

    FileAnalysis {
        function_cfgs,
        vra_results,
        visible_types: context::VisibleTypes::for_file(context, root_node, source),
        file_path: file_path.to_path_buf(),
    }
}

/// Compute VRA for all functions if any enabled rule needs it.
///
/// `pub(crate)` so the generated rule tests in
/// `src/rules/cert_c/integration/` can build the same VRA state the real
/// scan does -- a rule whose FP suppression depends on value ranges is
/// otherwise untestable from a `.c` fixture.
pub(crate) fn compute_vra_if_needed(
    needs_vra: bool,
    function_cfgs: &HashMap<usize, cfg::FunctionCfg>,
    root_node: &tree_sitter::Node,
    source: &str,
    prescan_summaries: &(impl crate::analyze::context::SummaryLookup + ?Sized),
    project_macros: &const_eval::MacroConstantMap,
    data_model: crate::settings::IntFacts,
) -> HashMap<usize, value_range::RangeAnalysisResult> {
    if !needs_vra || function_cfgs.is_empty() {
        return HashMap::new();
    }

    // Only compute macros and same-file summaries when VRA is actually needed.
    // Project-wide macros (from prescan) are merged under the current file's
    // own `#define`s, which win on collision. Without the project half, a
    // guard written against a header-defined constant -- `if (irq <
    // NORMAL_IRQ_OFFSET) return;` where that macro lives in a driver header
    // -- refined nothing, so every variable derived from the guarded one
    // stayed at its full type range for the rest of the function.
    let macros = const_eval::merged_macro_constants(project_macros, root_node, source, data_model);
    let mut file_summaries = function_summary::compute_summaries(
        root_node,
        source,
        &macros,
        true,
        &[],
        &std::collections::HashMap::new(),
        &std::collections::HashMap::new(),
    );

    // Augment same-file summaries with caller constant arg propagation so that
    // VRA can narrow parameter ranges (e.g. goodG2B passes data=2 to goodG2BSink).
    // Only a function whose caller set is closed is narrowed
    // (`FunctionSummary::caller_set_is_closed`), so these fresh summaries need
    // the address-escape half of that too: from this file's own value-position
    // names, and from the prescan's project-wide verdict, which also sees a
    // header's `static inline` referenced from the files that include it.
    {
        let mut value_position_identifiers = std::collections::HashSet::new();
        prescan::collect_value_position_identifiers(
            root_node,
            source,
            &mut value_position_identifiers,
        );
        if crate::settings::closure::declared() {
            function_summary::close_declared_caller_sets(&mut file_summaries);
        }
        prescan::mark_address_taken(&mut file_summaries, &value_position_identifiers);
        for (name, summary) in file_summaries.iter_mut() {
            if prescan_summaries.get(name).is_some_and(|s| s.address_taken) {
                summary.address_taken = true;
            }
        }
        let mut callsite_int_args = std::collections::HashMap::new();
        // The file's own every-configuration constants, as the prescan
        // folds them: not the project-wide map, where another file's macro
        // of the same name could stand in for this file's.
        prescan::collect_callsite_int_args_from_tree(
            root_node,
            source,
            &const_eval::cfg_prunable_constants(root_node, source, data_model),
            &mut callsite_int_args,
        );
        prescan::aggregate_callsite_int_args(
            &callsite_int_args,
            &mut file_summaries,
            &std::collections::HashSet::new(),
        );
    }

    // Same-file summaries in front of the prescan's (cross-file) ones, by
    // reference: a same-file definition answers for its own name.
    let summaries = crate::analyze::context::SummaryOverlay {
        first: &file_summaries,
        then: prescan_summaries,
    };

    let mut results = HashMap::new();
    for (&start_byte, func_cfg) in function_cfgs {
        if let Some(func_node) = find_function_at_byte(root_node, start_byte) {
            results.insert(
                start_byte,
                value_range::analyze_value_ranges(
                    func_cfg, &func_node, source, &macros, &summaries,
                ),
            );
        }
    }
    results
}

/// Find the function_definition node at a given start byte.
fn find_function_at_byte<'a>(
    node: &tree_sitter::Node<'a>,
    start_byte: usize,
) -> Option<tree_sitter::Node<'a>> {
    if node.kind() == "function_definition" && node.start_byte() == start_byte {
        return Some(*node);
    }
    for child in node.child_nodes() {
        // Prune: only descend into children whose range contains start_byte.
        if child.start_byte() <= start_byte && child.end_byte() >= start_byte {
            if let Some(found) = find_function_at_byte(&child, start_byte) {
                return Some(found);
            }
        }
    }
    None
}

/// Collect CFGs for all function_definition nodes in the AST.
/// Keyed by the function's start byte offset.
/// Uses file-level constants for dead-branch pruning in conditions.
pub fn collect_function_cfgs(
    node: &tree_sitter::Node,
    source: &str,
    cfgs: &mut HashMap<usize, cfg::FunctionCfg>,
    settings: &crate::settings::AnalysisSettings,
) {
    // Only values fixed in every configuration may prove a branch dead.
    let constants = const_eval::cfg_prunable_constants(node, source, settings.facts);
    let noreturn_names = noreturn::collect_noreturn_function_names(node, source, settings);
    collect_function_cfgs_with_constants(node, source, cfgs, &constants, &noreturn_names);
}

fn collect_function_cfgs_with_constants(
    node: &tree_sitter::Node,
    source: &str,
    cfgs: &mut HashMap<usize, cfg::FunctionCfg>,
    constants: &const_eval::MacroConstantMap,
    noreturn_names: &std::collections::HashSet<String>,
) {
    if node.kind() == "function_definition" {
        if let Some(function_cfg) = cfg::build_function_cfg_with_constants_and_noreturn(
            node,
            source,
            constants,
            noreturn_names,
        ) {
            cfgs.insert(node.start_byte(), function_cfg);
        }
    }
    for child in node.child_nodes() {
        collect_function_cfgs_with_constants(&child, source, cfgs, constants, noreturn_names);
    }
}

/// The trimmed source text of `line_number` in `file_path`, or a placeholder
/// string if the line is out of range.
pub fn get_code_snippet(file_path: &str, line_number: usize) -> Result<String> {
    let content = fs::read_to_string(file_path)?;
    let lines: Vec<&str> = content.lines().collect();

    if line_number > 0 && line_number <= lines.len() {
        let line = lines[line_number - 1].trim();
        Ok(line.to_string())
    } else {
        Ok("(line not found)".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_c(code: &str) -> (tree_sitter::Tree, String) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        (tree, code.to_string())
    }

    // -- collect_c_files / build_path_ignore --

    #[test]
    fn collect_c_files_respects_toolchain_toml_ignore() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("toolchain.toml"),
            "[ignore]\npaths = [\"vendor/**\"]\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("vendor")).unwrap();
        fs::write(dir.path().join("vendor").join("lib.c"), "int x;\n").unwrap();
        fs::write(dir.path().join("main.c"), "int y;\n").unwrap();

        let project_source = ProjectSource::open(dir.path().to_str().unwrap()).unwrap();
        let c_files = collect_c_files(&project_source, false, &[]).unwrap();

        assert!(c_files.iter().any(|f| f.ends_with("main.c")));
        assert!(!c_files.iter().any(|f| f.contains("vendor")));
    }

    #[test]
    fn collect_c_files_merges_toolchain_and_cli_excludes() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("toolchain.toml"),
            "[ignore]\npaths = [\"vendor/**\"]\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("vendor")).unwrap();
        fs::write(dir.path().join("vendor").join("lib.c"), "int x;\n").unwrap();
        fs::write(dir.path().join("generated.c"), "int z;\n").unwrap();
        fs::write(dir.path().join("main.c"), "int y;\n").unwrap();

        let project_source = ProjectSource::open(dir.path().to_str().unwrap()).unwrap();
        let c_files =
            collect_c_files(&project_source, false, &["**/generated.c".to_string()]).unwrap();

        assert!(c_files.iter().any(|f| f.ends_with("main.c")));
        assert!(!c_files.iter().any(|f| f.contains("vendor")));
        assert!(!c_files.iter().any(|f| f.ends_with("generated.c")));
    }

    #[test]
    fn build_path_ignore_skips_invalid_pattern_but_keeps_valid_ones() {
        let dir = tempfile::tempdir().unwrap();
        let project_source = ProjectSource::open(dir.path().to_str().unwrap()).unwrap();
        let ignore =
            build_path_ignore(&project_source, &["[".to_string(), "vendor/**".to_string()])
                .unwrap();
        assert!(ignore.is_ignored(std::path::Path::new("vendor/lib.c")));
        assert!(!ignore.is_ignored(std::path::Path::new("src/main.c")));
    }

    // -- collect_function_cfgs --

    #[test]
    fn test_collect_function_cfgs_basic() {
        let code = "void foo(void) { int x = 1; } void bar(int n) { return; }";
        let (tree, source) = parse_c(code);
        let mut cfgs = HashMap::new();
        collect_function_cfgs(&tree.root_node(), &source, &mut cfgs, &Default::default());
        assert_eq!(cfgs.len(), 2);
    }

    #[test]
    fn test_collect_function_cfgs_empty_source() {
        let code = "int x = 42;"; // no functions
        let (tree, source) = parse_c(code);
        let mut cfgs = HashMap::new();
        collect_function_cfgs(&tree.root_node(), &source, &mut cfgs, &Default::default());
        assert!(cfgs.is_empty());
    }

    // -- find_function_at_byte --

    #[test]
    fn test_find_function_at_byte_found() {
        let code = "void foo(void) { }";
        let (tree, _source) = parse_c(code);
        let root = tree.root_node();
        let func = root.child(0).unwrap();
        let start = func.start_byte();
        let found = find_function_at_byte(&root, start);
        assert!(found.is_some());
        assert_eq!(found.unwrap().kind(), "function_definition");
    }

    #[test]
    fn test_find_function_at_byte_not_found() {
        let code = "void foo(void) { }";
        let (tree, _source) = parse_c(code);
        let found = find_function_at_byte(&tree.root_node(), 9999);
        assert!(found.is_none());
    }

    #[test]
    fn test_find_function_at_byte_multiple() {
        let code = "void a(void) {} void b(void) {}";
        let (tree, _source) = parse_c(code);
        let root = tree.root_node();
        // Find second function
        let second_func = root.child(1).unwrap();
        let start = second_func.start_byte();
        let found = find_function_at_byte(&root, start);
        assert!(found.is_some());
    }

    // -- get_code_snippet --

    #[test]
    fn test_get_code_snippet() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("test.c");
        std::fs::write(&file, "int x = 1;\nint y = 2;\nint z = 3;\n").unwrap();
        let path = file.to_string_lossy().to_string();

        assert_eq!(get_code_snippet(&path, 1).unwrap(), "int x = 1;");
        assert_eq!(get_code_snippet(&path, 2).unwrap(), "int y = 2;");
        assert_eq!(get_code_snippet(&path, 3).unwrap(), "int z = 3;");
        assert_eq!(get_code_snippet(&path, 99).unwrap(), "(line not found)");
    }

    #[test]
    fn test_get_code_snippet_trims_whitespace() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("test.c");
        std::fs::write(&file, "    int x = 1;\n").unwrap();
        let path = file.to_string_lossy().to_string();
        assert_eq!(get_code_snippet(&path, 1).unwrap(), "int x = 1;");
    }

    // -- compute_vra_if_needed --

    #[test]
    fn test_compute_vra_not_needed() {
        let cfgs = HashMap::new();
        let code = "void f(void) {}";
        let (tree, source) = parse_c(code);
        let summaries = HashMap::new();
        let results = compute_vra_if_needed(
            false,
            &cfgs,
            &tree.root_node(),
            &source,
            &summaries,
            &const_eval::MacroConstantMap::new(),
            Default::default(),
        );
        assert!(results.is_empty());
    }

    #[test]
    fn test_compute_vra_empty_cfgs() {
        let cfgs = HashMap::new();
        let code = "void f(void) {}";
        let (tree, source) = parse_c(code);
        let summaries = HashMap::new();
        let results = compute_vra_if_needed(
            true,
            &cfgs,
            &tree.root_node(),
            &source,
            &summaries,
            &const_eval::MacroConstantMap::new(),
            Default::default(),
        );
        assert!(results.is_empty());
    }

    // -- AnalysisResults / SuppressedViolation construction --

    #[test]
    fn test_analysis_results_struct() {
        let results = AnalysisResults {
            violations: vec![],
            suppressed: vec![],
            macro_gaps: None,
            failures: vec![],
            abandoned_rules: vec![],
            not_converged: vec![],
        };
        assert!(results.violations.is_empty());
        assert!(results.suppressed.is_empty());
    }
}
