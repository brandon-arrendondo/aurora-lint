//! Dev tool: dump the tree-sitter-c parse tree (S-expression) for a snippet,
//! using the EXACT grammar version sqc depends on. Used by the macro-expansion
//! Phase 0 spike (task 184) to confirm how function-like macro invocations
//! parse. Reads C source from stdin; prints the S-expression and error flag.
//!
//!   echo 'CODE' | cargo run --example dump_ast

use std::io::Read;
use tree_sitter::Parser;

fn main() {
    let mut source = String::new();
    std::io::stdin().read_to_string(&mut source).unwrap();

    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_c::language()).unwrap();
    let tree = parser.parse(&source, None).unwrap();
    let root = tree.root_node();

    println!("has_error: {}", root.has_error());
    println!("--- s-expression ---");
    print_node(&root, &source, 0);
}

fn print_node(node: &tree_sitter::Node, src: &str, depth: usize) {
    let indent = "  ".repeat(depth);
    let kind = node.kind();
    let named = node.is_named();
    let extra = if node.is_missing() {
        " MISSING".to_string()
    } else if node.is_error() {
        " ERROR".to_string()
    } else if node.child_count() == 0 && named {
        // leaf: show text
        let t = node.utf8_text(src.as_bytes()).unwrap_or("");
        format!(" '{}'", t.replace('\n', "\\n"))
    } else {
        String::new()
    };
    // field name if present (relative to parent) is hard to get here; print kind only
    let marker = if named { "" } else { "· " };
    println!("{}{}{}{}", indent, marker, kind, extra);
    for i in 0..node.child_count() {
        if let Some(c) = node.child(i) {
            print_node(&c, src, depth + 1);
        }
    }
}
