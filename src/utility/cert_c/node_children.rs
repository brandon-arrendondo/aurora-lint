// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! A node's children in order, at linear cost in their number.
//!
//! `Node::child(i)` and `named_child(i)` walk from the first child, so
//! indexing every child of a node is O(k²) in its child count: every comment
//! and declaration at file scope is a child of the translation unit, and an
//! index loop over the root made a file of comments quadratic in its length.
//! `Node::children(&mut node.walk())` is linear, but `walk()` allocates a
//! cursor, which on the small nodes most loops visit costs more than the
//! indexing it replaces. [`NodeChildren`] indexes a node with few children
//! and takes a cursor only for a wide one, so both cases stay cheap. The
//! sequence is the same either way.

use tree_sitter::{Node, TreeCursor};

/// Above this many children, iterate with a cursor instead of by index.
const CURSOR_ABOVE: usize = 32;

/// `child_nodes` / `named_child_nodes` on a node.
pub trait NodeChildren<'a> {
    /// Every child, in order: what `0..child_count()` with `child(i)` gives.
    fn child_nodes(&self) -> ChildNodes<'a>;
    /// Every named child, in order: what `0..named_child_count()` with
    /// `named_child(i)` gives.
    fn named_child_nodes(&self) -> ChildNodes<'a>;
}

impl<'a> NodeChildren<'a> for Node<'a> {
    fn child_nodes(&self) -> ChildNodes<'a> {
        ChildNodes::new(*self, false)
    }

    fn named_child_nodes(&self) -> ChildNodes<'a> {
        ChildNodes::new(*self, true)
    }
}

/// The iterator [`NodeChildren`] returns.
pub struct ChildNodes<'a> {
    node: Node<'a>,
    named: bool,
    next: usize,
    count: usize,
    /// A cursor on the next child, for a node with many children.
    cursor: Option<TreeCursor<'a>>,
}

impl<'a> ChildNodes<'a> {
    fn new(node: Node<'a>, named: bool) -> Self {
        let count = if named {
            node.named_child_count()
        } else {
            node.child_count()
        };
        let cursor = (count > CURSOR_ABOVE).then(|| {
            let mut cursor = node.walk();
            cursor.goto_first_child();
            cursor
        });
        Self {
            node,
            named,
            next: 0,
            count,
            cursor,
        }
    }
}

impl<'a> Iterator for ChildNodes<'a> {
    type Item = Node<'a>;

    fn next(&mut self) -> Option<Node<'a>> {
        if self.next >= self.count {
            return None;
        }
        let i = self.next;
        self.next += 1;
        match &mut self.cursor {
            // As `Node::children` / `named_children` step their cursor.
            Some(cursor) => {
                if self.named {
                    while !cursor.node().is_named() {
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
                let node = cursor.node();
                cursor.goto_next_sibling();
                Some(node)
            }
            None if self.named => self.node.named_child(i),
            None => self.node.child(i),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.count - self.next;
        (left, Some(left))
    }
}

impl ExactSizeIterator for ChildNodes<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        parser.parse(code, None).unwrap()
    }

    /// Both strategies give exactly what indexing gives, at every node, on
    /// nodes below and above the threshold.
    #[test]
    fn child_nodes_are_what_indexing_gives() {
        let mut code = String::from("int f(int a, int b) { return a + b; }\n");
        for i in 0..(CURSOR_ABOVE * 3) {
            code.push_str(&format!("/* c{i} */ int g{i} = {i};\n"));
        }
        code.push_str("void h(void) {\n");
        for i in 0..(CURSOR_ABOVE * 2) {
            code.push_str(&format!("    h{i}(); /* note */\n"));
        }
        code.push_str("}\n");
        let tree = parse(&code);
        let mut wide = 0;
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            let by_index: Vec<_> = (0..node.child_count())
                .filter_map(|i| node.child(i))
                .collect();
            let named_by_index: Vec<_> = (0..node.named_child_count())
                .filter_map(|i| node.named_child(i))
                .collect();
            assert_eq!(node.child_nodes().collect::<Vec<_>>(), by_index);
            assert_eq!(node.named_child_nodes().collect::<Vec<_>>(), named_by_index);
            assert_eq!(node.child_nodes().len(), by_index.len());
            wide += usize::from(node.child_count() > CURSOR_ABOVE);
            stack.extend(by_index);
        }
        assert!(
            wide >= 2,
            "the source has nodes on both sides of the threshold"
        );
    }
}
