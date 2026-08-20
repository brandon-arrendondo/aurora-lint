//! Task 471: walk every wiki_*.c CERT fixture and flag ones whose tree-sitter
//! parse tree contains an ERROR node -- i.e. fixtures that are not valid
//! standalone C, regardless of whether they textually match the current
//! wiki content (task 328's containment heuristic only checked the latter
//! and missed these). A fixture with an ERROR node still "passes" its
//! generated test trivially (fail tests may or may not still detect a
//! violation depending on where the ERROR lands; pass tests almost always
//! pass since no violation gets computed on the garbage), so this is a
//! purely mechanical, higher-confidence signal that the fixture doesn't
//! exercise anything real.
//!
//!   cargo run --example audit_wiki_fixture_errors > /tmp/wiki_fixture_errors.txt

use std::path::Path;
use tree_sitter::Parser;

fn main() {
    let mut parser = Parser::new();
    parser.set_language(&sqc::parser::c_language()).unwrap();

    let mut files = Vec::new();
    walk(Path::new("src/rules/cert_c"), &mut files);
    files.sort();

    let mut error_count = 0;
    for path in &files {
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("SKIP (read error): {} ({e})", path.display());
                continue;
            }
        };
        let tree = match parser.parse(&source, None) {
            Some(t) => t,
            None => {
                println!("PARSE_FAILED\t{}", path.display());
                error_count += 1;
                continue;
            }
        };
        if tree.root_node().has_error() {
            error_count += 1;
            let mut snippets = Vec::new();
            collect_error_snippets(&tree.root_node(), &source, &mut snippets);
            println!("HAS_ERROR\t{}\t{}", path.display(), snippets.join(" | "));
        }
    }

    eprintln!(
        "\n{error_count}/{} wiki_*.c fixtures have a tree-sitter ERROR node",
        files.len()
    );
}

fn collect_error_snippets(node: &tree_sitter::Node, source: &str, out: &mut Vec<String>) {
    if node.is_error() || node.is_missing() {
        let start = node.start_position().row + 1;
        let text = node.utf8_text(source.as_bytes()).unwrap_or("");
        let snippet: String = text.chars().take(60).collect();
        out.push(format!("L{}:{:?}", start, snippet.replace('\n', "\\n")));
        return; // don't descend into an already-flagged error subtree
    }
    for i in 0..node.child_count() {
        if let Some(c) = node.child(i) {
            collect_error_snippets(&c, source, out);
        }
    }
}

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with("wiki_") && name.ends_with(".c") {
                out.push(path);
            }
        }
    }
}
