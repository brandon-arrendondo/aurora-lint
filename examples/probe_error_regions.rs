//! Dev probe (tools_sqc task 1052): measure the blast radius of collapsed
//! top-level `ERROR` regions across a real codebase.
//!
//! For every file handed to it on stdin (one path per line) this parses with
//! the SHIPPED pipeline -- `CParser::parse_file`, so all five pre-parse
//! blanking passes and `parse_with_recovery` run, and the prescan's
//! `RepairMacros` are wired in exactly as `analyze::analyze_project` wires
//! them -- then reports, as one JSON object per line:
//!
//!   * how much of the file the largest top-level `ERROR` node spans, and
//!   * how many `function_definition` nodes land inside that region versus
//!     outside it.
//!
//! Everything inside such a region is invisible to every rule but the
//! function-name collectors, so `fn_inside` is the count of definitions no
//! parameter-, return-type- or body-reading rule can see.
//!
//!   ls project/**/*.c | cargo run --release --example probe_error_regions -- -d project
//!
//! `-d` is repeatable and feeds the prescan; omit it to probe with an empty
//! repair-macro table (which is what a `-d`-less scan actually does).

use std::io::{BufRead, Write};

use rayon::prelude::*;
use tree_sitter::Node;

use aurora_lint::analyze::prescan;
use aurora_lint::analyze::unknown_identifier_recovery::RepairMacros;
use aurora_lint::parser::CParser;
use aurora_lint::utility::cert_c::ast_utils;

/// Per-file counts. Field names are the JSON keys the aggregator reads.
struct FileProbe {
    path: String,
    bytes: usize,
    /// Direct `ERROR` children of the `translation_unit`.
    top_error_count: usize,
    /// Bytes spanned by the largest of them (0 when there are none).
    top_error_bytes: usize,
    /// `function_definition` nodes anywhere under any top-level `ERROR`.
    fn_inside: usize,
    /// `function_definition` nodes everywhere else.
    fn_outside: usize,
    /// `function_declarator` nodes under a top-level `ERROR` that are NOT
    /// under a `function_definition` -- the declaration shape
    /// `ast_utils::function_names_in_error_declaration` reads names out of,
    /// and the one whose parameters and return type are still lost.
    stranded_declarators: usize,
    /// Of `fn_inside`, how many yield parameters to
    /// `ast_utils::get_function_parameters`. Most rule walkers recurse into
    /// `ERROR` rather than stopping at it, so a definition recovery managed
    /// to build there is only *lost* if its declarator is unreadable -- this
    /// separates "hidden by the region" from "structurally intact inside it".
    fn_inside_params_ok: usize,
    /// The same check outside every `ERROR`, as a control.
    fn_outside_params_ok: usize,
    /// Well-formed `declaration` nodes under a top-level `ERROR` -- visible
    /// to the ordinary declaration walk despite their ancestor.
    decls_inside: usize,
}

fn main() {
    let mut prescan_dirs: Vec<String> = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-d" | "--directory" => {
                if let Some(dir) = args.next() {
                    prescan_dirs.push(dir);
                }
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let repair_macros = if prescan_dirs.is_empty() {
        RepairMacros::default()
    } else {
        match prescan::prescan_directories(&prescan_dirs, None, false) {
            Ok(context) => RepairMacros::from_context(&context),
            Err(err) => {
                eprintln!("prescan failed: {err:#}");
                std::process::exit(1);
            }
        }
    };
    let repair_macros = std::sync::Arc::new(repair_macros);

    let files: Vec<String> = std::io::stdin()
        .lock()
        .lines()
        .map_while(Result::ok)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    eprintln!(
        "probing {} files with {} prescan dir(s)",
        files.len(),
        prescan_dirs.len()
    );

    let probes: Vec<FileProbe> = files
        .par_iter()
        .filter_map(|path| probe_file(path, &repair_macros))
        .collect();

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for probe in &probes {
        writeln!(
            out,
            r#"{{"path":{},"bytes":{},"top_error_count":{},"top_error_bytes":{},"fn_inside":{},"fn_outside":{},"stranded_declarators":{},"fn_inside_params_ok":{},"fn_outside_params_ok":{},"decls_inside":{}}}"#,
            json_string(&probe.path),
            probe.bytes,
            probe.top_error_count,
            probe.top_error_bytes,
            probe.fn_inside,
            probe.fn_outside,
            probe.stranded_declarators,
            probe.fn_inside_params_ok,
            probe.fn_outside_params_ok,
            probe.decls_inside,
        )
        .expect("write probe line");
    }
}

fn probe_file(path: &str, repair_macros: &std::sync::Arc<RepairMacros>) -> Option<FileProbe> {
    let mut parser = CParser::new().ok()?;
    parser.set_repair_macros(std::sync::Arc::clone(repair_macros));
    let (tree, source) = parser.parse_file(path).ok()?;
    let root = tree.root_node();

    let mut probe = FileProbe {
        path: path.to_string(),
        bytes: source.len(),
        top_error_count: 0,
        top_error_bytes: 0,
        fn_inside: 0,
        fn_outside: 0,
        stranded_declarators: 0,
        fn_inside_params_ok: 0,
        fn_outside_params_ok: 0,
        decls_inside: 0,
    };

    for i in 0..root.child_count() {
        let Some(child) = root.child(i) else { continue };
        if child.kind() == "ERROR" {
            probe.top_error_count += 1;
            let span = child.end_byte().saturating_sub(child.start_byte());
            probe.top_error_bytes = probe.top_error_bytes.max(span);
            count_inside_error(&child, &source, &mut probe);
        } else {
            count_outside_error(&child, &source, &mut probe);
        }
    }

    Some(probe)
}

/// Walk a top-level `ERROR` subtree, counting the definitions recovery did
/// manage to build and the bare declarators it did not.
fn count_inside_error(node: &Node, source: &str, probe: &mut FileProbe) {
    if node.kind() == "function_definition" {
        probe.fn_inside += 1;
        if ast_utils::get_function_parameters(node, source).is_some() {
            probe.fn_inside_params_ok += 1;
        }
        // Its own declarator is attached to a real definition, so it is not
        // stranded; the body below it holds nothing this probe counts.
        return;
    }
    if node.kind() == "function_declarator" {
        probe.stranded_declarators += 1;
    }
    if node.kind() == "declaration" {
        probe.decls_inside += 1;
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            count_inside_error(&child, source, probe);
        }
    }
}

/// Definitions outside every top-level `ERROR` node -- what the analyzer
/// actually sees today.
fn count_outside_error(node: &Node, source: &str, probe: &mut FileProbe) {
    if node.kind() == "function_definition" {
        probe.fn_outside += 1;
        if ast_utils::get_function_parameters(node, source).is_some() {
            probe.fn_outside_params_ok += 1;
        }
        return;
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            count_outside_error(&child, source, probe);
        }
    }
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
