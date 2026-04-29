pub mod cfg;
pub mod const_eval;
pub mod context;
pub mod dataflow;
pub mod function_summary;
pub mod init_state;
pub mod null_state;
pub mod prescan;
pub mod suppression;
pub mod value_range;

use super::files::ProjectSource;
use super::manifest::RuleManifest;
use super::parser::CParser;
use super::progress::ProgressReporter;
use super::rules::{RuleRegistry, RuleViolation};
use suppression::SuppressionManager;

use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A violation that was suppressed by an inline SQC-SUPPRESS comment.
pub struct SuppressedViolation {
    pub violation: RuleViolation,
    pub justification: String,
}

/// Results from project analysis, containing both active and suppressed violations.
pub struct AnalysisResults {
    pub violations: Vec<RuleViolation>,
    pub suppressed: Vec<SuppressedViolation>,
}

pub fn analyze_project(
    project_source: &ProjectSource,
    manifest: &RuleManifest,
    progress: Option<&dyn ProgressReporter>,
    directories: &[String],
    include_paths: &[String],
    diff_only: bool,
    suppress_file: Option<&str>,
    save_prescan: Option<&str>,
    load_prescan: Option<&str>,
    jobs: usize,
) -> Result<AnalysisResults> {
    let mut violations = Vec::new();
    let mut suppressed = Vec::new();
    let registry = RuleRegistry::new();

    // Pre-compute whether any enabled rule needs VRA (used by prescan + per-file analysis)
    let needs_vra = manifest
        .enabled_rules()
        .any(|(rule_id, _)| registry.get_rule(rule_id).is_some_and(|r| r.needs_vra()));

    // Load or compute cross-file context
    let mut context = if let Some(cache_path) = load_prescan {
        let path = std::path::Path::new(cache_path);
        if path.exists() {
            if let Some(reporter) = progress {
                reporter.report_prescan_start(0);
            }
            let ctx = context::ProjectContext::load_from_file(path)?;
            if let Some(reporter) = progress {
                reporter.report_prescan_complete(ctx.known_functions.len());
            }
            ctx
        } else {
            anyhow::bail!("Prescan cache file not found: {}", cache_path);
        }
    } else if directories.is_empty() {
        context::ProjectContext::new()
    } else {
        prescan::prescan_directories(directories, progress, needs_vra)?
    };

    // Resolve #include directives against include search paths
    if !include_paths.is_empty() {
        let c_files = if diff_only {
            project_source.get_modified_c_files()?
        } else {
            project_source.get_c_files()?
        };
        prescan::resolve_includes(&c_files, include_paths, &mut context, progress, needs_vra)?;
    }

    // Save prescan cache if requested (after prescan + include resolution)
    if let Some(cache_path) = save_prescan {
        context.save_to_file(std::path::Path::new(cache_path))?;
        eprintln!(
            "Saved prescan cache ({} functions, {} summaries) to: {}",
            context.known_functions.len(),
            context.function_summaries.len(),
            cache_path,
        );
    }

    if context.has_cross_file_data() {
        for rule in registry.all_rules() {
            rule.set_project_context(&context);
        }
    }

    // Validate that all enabled rules are implemented
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

    let mut c_files = if diff_only {
        project_source.get_modified_c_files()?
    } else {
        project_source.get_c_files()?
    };

    // LPT scheduling: sort files by size descending so largest files are dispatched first.
    // Combined with par_bridge() demand-driven dispatch, this implements Graham's LPT
    // algorithm (1969) for makespan minimization — (4/3 - 1/3m) approximation ratio.
    c_files
        .sort_by_cached_key(|f| std::cmp::Reverse(fs::metadata(f).map(|m| m.len()).unwrap_or(0)));

    let total_files = c_files.len();
    let mut suppression_manager = SuppressionManager::new();

    // Load TOML suppression file if provided or auto-detected
    let toml_path = suppress_file.map(String::from).or_else(|| {
        let auto_path =
            std::path::Path::new(project_source.get_root_path()).join(".sqc-suppress.toml");
        if auto_path.exists() {
            auto_path.to_str().map(String::from)
        } else {
            None
        }
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
            Err(e) => {
                eprintln!("Warning: {}", e);
            }
        }
    }

    // Determine effective parallelism
    let effective_jobs = if jobs == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        jobs
    };

    if effective_jobs > 1 && total_files > 1 {
        // Parallel analysis with rayon — per-file parser and rule registry
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(effective_jobs)
            .build()?;
        let has_cross_file_data = context.has_cross_file_data();
        let file_counter = AtomicUsize::new(0);

        let results: Vec<_> = pool.install(|| {
            c_files
                .iter()
                .par_bridge()
                .map(|file_path| {
                    if let Some(reporter) = progress {
                        if reporter.is_cancelled() {
                            return (Vec::new(), Vec::new());
                        }
                    }

                    let mut parser = match CParser::new() {
                        Ok(p) => p,
                        Err(_) => return (Vec::new(), Vec::new()),
                    };
                    let file_registry = RuleRegistry::new();
                    if has_cross_file_data {
                        for rule in file_registry.all_rules() {
                            rule.set_project_context(&context);
                        }
                    }
                    let mut file_supp = suppression_manager.clone();

                    let mut file_violations = Vec::new();
                    let mut file_suppressed = Vec::new();

                    if let Ok((tree, source)) = parser.parse_file(file_path) {
                        let root_node = tree.root_node();
                        let mut function_cfgs: HashMap<usize, cfg::FunctionCfg> = HashMap::new();
                        collect_function_cfgs(&root_node, &source, &mut function_cfgs);
                        let vra_results = compute_vra_if_needed(
                            needs_vra,
                            &function_cfgs,
                            &root_node,
                            &source,
                            &context.function_summaries,
                        );
                        file_supp.extract_from_source(file_path, &source);

                        for (rule_id, rule_config) in manifest.enabled_rules() {
                            if let Some(rule) = file_registry.get_rule(rule_id) {
                                if !rule.applies_to_file(file_path) {
                                    continue;
                                }
                                rule.set_function_cfgs(&function_cfgs);
                                if !vra_results.is_empty() {
                                    rule.set_vra_results(&vra_results);
                                }
                                let mut rule_violations = rule.check(&root_node, &source);
                                for v in &mut rule_violations {
                                    v.file_path = file_path.clone();
                                    v.severity = rule_config
                                        .severity
                                        .clone()
                                        .unwrap_or_else(|| rule.severity());
                                }
                                for v in rule_violations {
                                    if let Some(j) = file_supp.should_suppress(
                                        file_path, rule_id, v.line, &source, &v.message,
                                    ) {
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
                    }

                    let completed = file_counter.fetch_add(1, Ordering::Relaxed) + 1;
                    if let Some(reporter) = progress {
                        reporter.report_file(completed, total_files, file_path, "");
                    }

                    (file_violations, file_suppressed)
                })
                .collect()
        });

        for (v, s) in results {
            violations.extend(v);
            suppressed.extend(s);
        }

        // Sort for deterministic output
        violations.sort_by(|a, b| {
            a.file_path
                .cmp(&b.file_path)
                .then(a.line.cmp(&b.line))
                .then(a.column.cmp(&b.column))
                .then(a.rule_id.cmp(&b.rule_id))
        });

        if let Some(reporter) = progress {
            reporter.report_complete(violations.len());
        }

        return Ok(AnalysisResults {
            violations,
            suppressed,
        });
    }

    // Sequential analysis (single-threaded)
    // Fresh registry per file to prevent cross-file state leakage from RefCell fields
    let mut parser = CParser::new()?;
    let has_cross_file_data = context.has_cross_file_data();

    for (file_idx, file_path) in c_files.iter().enumerate() {
        // Check for cancellation before processing each file
        if let Some(reporter) = progress {
            if reporter.is_cancelled() {
                // Return partial results collected so far
                break;
            }
        }

        if let Ok((tree, source)) = parser.parse_file(file_path) {
            let root_node = tree.root_node();

            // Build CFGs for all function definitions in this file
            let mut function_cfgs: HashMap<usize, cfg::FunctionCfg> = HashMap::new();
            collect_function_cfgs(&root_node, &source, &mut function_cfgs);

            // Compute VRA if any enabled rule needs it
            let vra_results = compute_vra_if_needed(
                needs_vra,
                &function_cfgs,
                &root_node,
                &source,
                &context.function_summaries,
            );

            // Extract suppressions from the current file
            suppression_manager.extract_from_source(file_path, &source);

            // Create fresh rule instances per file (matches parallel mode behavior)
            let file_registry = RuleRegistry::new();
            if has_cross_file_data {
                for rule in file_registry.all_rules() {
                    rule.set_project_context(&context);
                }
            }

            for (rule_id, rule_config) in manifest.enabled_rules() {
                // Check cancellation between rules
                if let Some(reporter) = progress {
                    if reporter.is_cancelled() {
                        break;
                    }
                    // Report progress with current file and rule (full relative path)
                    reporter.report_file(file_idx + 1, total_files, file_path, rule_id);
                }

                // Check if rule is implemented
                if let Some(rule) = file_registry.get_rule(rule_id) {
                    // Skip rules that don't apply to this file type (e.g. header-only rules)
                    if !rule.applies_to_file(file_path) {
                        continue;
                    }
                    // Provide CFGs for flow-sensitive rules (e.g. EXP34-C)
                    rule.set_function_cfgs(&function_cfgs);
                    // Provide VRA results for integer-range-sensitive rules
                    if !vra_results.is_empty() {
                        rule.set_vra_results(&vra_results);
                    }
                    let mut file_violations = rule.check(&root_node, &source);

                    // Set file path and severity on all violations
                    for violation in &mut file_violations {
                        violation.file_path = file_path.clone();
                        violation.severity = rule_config
                            .severity
                            .clone()
                            .unwrap_or_else(|| rule.severity());
                    }

                    // Partition into active and suppressed violations
                    for violation in file_violations {
                        if let Some(justification) = suppression_manager.should_suppress(
                            file_path,
                            rule_id,
                            violation.line,
                            &source,
                            &violation.message,
                        ) {
                            suppressed.push(SuppressedViolation {
                                justification: justification.to_string(),
                                violation,
                            });
                        } else {
                            violations.push(violation);
                        }
                    }
                }
                // Note: Unimplemented rules are already warned about at the start of analysis
            }
        }
    }

    // Report completion
    if let Some(reporter) = progress {
        reporter.report_complete(violations.len());
    }

    Ok(AnalysisResults {
        violations,
        suppressed,
    })
}

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

    // Get the code line, stripping any existing SQC-SUPPRESS comment
    let raw_line = lines[line - 1];
    let code = if let Some(pos) = raw_line.find("// SQC-SUPPRESS") {
        &raw_line[..pos]
    } else if let Some(pos) = raw_line.find("/* SQC-SUPPRESS") {
        &raw_line[..pos]
    } else {
        raw_line
    };

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

    println!("Add on the line before, or inline:");
    println!(
        "// SQC-SUPPRESS: {} HASH:{} JUSTIFICATION: \"TODO: Add justification\"",
        rule_id, hash
    );
    println!();
    println!("Or add to .sqc-suppress.toml (for read-only codebases):");
    println!("[[suppression]]");
    println!("file = \"{}\"", filename);
    println!("rule = \"{}\"", rule_id);
    println!("hash = \"{}\"", hash);
    println!("justification = \"TODO: Add justification\"");

    Ok(())
}

/// Compute VRA for all functions if any enabled rule needs it.
fn compute_vra_if_needed(
    needs_vra: bool,
    function_cfgs: &HashMap<usize, cfg::FunctionCfg>,
    root_node: &tree_sitter::Node,
    source: &str,
    prescan_summaries: &HashMap<String, function_summary::FunctionSummary>,
) -> HashMap<usize, value_range::RangeAnalysisResult> {
    if !needs_vra || function_cfgs.is_empty() {
        return HashMap::new();
    }

    // Only compute macros and same-file summaries when VRA is actually needed
    let macros = const_eval::collect_macro_constants(root_node, source);
    let mut file_summaries = function_summary::compute_summaries(
        root_node,
        source,
        &macros,
        true,
        &[],
        &std::collections::HashMap::new(),
    );

    // Augment same-file summaries with caller constant arg propagation so that
    // VRA can narrow parameter ranges (e.g. goodG2B passes data=2 to goodG2BSink).
    {
        let mut callsite_int_args = std::collections::HashMap::new();
        prescan::collect_callsite_int_args_from_tree(root_node, source, &mut callsite_int_args);
        prescan::aggregate_callsite_int_args(
            &callsite_int_args,
            &mut file_summaries,
            &std::collections::HashSet::new(),
        );
    }

    // Merge prescan (cross-file) summaries with same-file summaries by reference.
    // Only clone+extend if both sides are non-empty; otherwise use whichever is available.
    let merged;
    let summaries: &HashMap<String, function_summary::FunctionSummary> =
        if prescan_summaries.is_empty() {
            &file_summaries
        } else if file_summaries.is_empty() {
            prescan_summaries
        } else {
            merged = {
                let mut m = prescan_summaries.clone();
                m.extend(file_summaries);
                m
            };
            &merged
        };

    let mut results = HashMap::new();
    for (&start_byte, func_cfg) in function_cfgs {
        if let Some(func_node) = find_function_at_byte(root_node, start_byte) {
            results.insert(
                start_byte,
                value_range::analyze_value_ranges(func_cfg, &func_node, source, &macros, summaries),
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
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
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
) {
    let constants = const_eval::collect_macro_constants(node, source);
    collect_function_cfgs_with_constants(node, source, cfgs, &constants);
}

fn collect_function_cfgs_with_constants(
    node: &tree_sitter::Node,
    source: &str,
    cfgs: &mut HashMap<usize, cfg::FunctionCfg>,
    constants: &const_eval::MacroConstantMap,
) {
    if node.kind() == "function_definition" {
        if let Some(function_cfg) = cfg::build_function_cfg_with_constants(node, source, constants)
        {
            cfgs.insert(node.start_byte(), function_cfg);
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_function_cfgs_with_constants(&child, source, cfgs, constants);
        }
    }
}

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
        parser.set_language(&tree_sitter_c::language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        (tree, code.to_string())
    }

    // -- collect_function_cfgs --

    #[test]
    fn test_collect_function_cfgs_basic() {
        let code = "void foo(void) { int x = 1; } void bar(int n) { return; }";
        let (tree, source) = parse_c(code);
        let mut cfgs = HashMap::new();
        collect_function_cfgs(&tree.root_node(), &source, &mut cfgs);
        assert_eq!(cfgs.len(), 2);
    }

    #[test]
    fn test_collect_function_cfgs_empty_source() {
        let code = "int x = 42;"; // no functions
        let (tree, source) = parse_c(code);
        let mut cfgs = HashMap::new();
        collect_function_cfgs(&tree.root_node(), &source, &mut cfgs);
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
        let results = compute_vra_if_needed(false, &cfgs, &tree.root_node(), &source, &summaries);
        assert!(results.is_empty());
    }

    #[test]
    fn test_compute_vra_empty_cfgs() {
        let cfgs = HashMap::new();
        let code = "void f(void) {}";
        let (tree, source) = parse_c(code);
        let summaries = HashMap::new();
        let results = compute_vra_if_needed(true, &cfgs, &tree.root_node(), &source, &summaries);
        assert!(results.is_empty());
    }

    // -- AnalysisResults / SuppressedViolation construction --

    #[test]
    fn test_analysis_results_struct() {
        let results = AnalysisResults {
            violations: vec![],
            suppressed: vec![],
        };
        assert!(results.violations.is_empty());
        assert!(results.suppressed.is_empty());
    }
}
