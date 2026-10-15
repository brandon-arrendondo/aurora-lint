//! Whether any node of a subtree satisfies a predicate, remembered per node.
//!
//! `query::find_descendants(node, p).is_empty()` costs `node`'s whole
//! subtree. A rule that asks it of every operand of every operator of an
//! expression asks it of nested subtrees, and pays the square of the
//! expression's length. A node's answer is its own or any child's, so
//! answering bottom-up once per node, and remembering each, costs every node
//! once however many subtrees are asked about.

use std::cell::RefCell;
use std::collections::HashMap;

use tree_sitter::Node;

/// Answers for one predicate over one tree, by node id.
#[derive(Default)]
pub struct SubtreeAny(RefCell<HashMap<usize, bool>>);

impl SubtreeAny {
    /// Forget every answer, before asking about another tree.
    pub fn clear(&self) {
        self.0.borrow_mut().clear();
    }

    /// Whether `node` or any node under it satisfies `pred`: the same as
    /// `!query::find_descendants(node, pred).is_empty()`, for a caller that
    /// passes the same predicate every time it asks this memo.
    ///
    /// Filled in post-order on a stack of its own, so a subtree thousands of
    /// levels deep is not thousands of calls deep.
    pub fn any(&self, node: &Node, pred: impl Fn(&Node) -> bool) -> bool {
        if let Some(&known) = self.0.borrow().get(&node.id()) {
            return known;
        }
        let mut stack = vec![(*node, false)];
        while let Some((n, children_done)) = stack.pop() {
            if self.0.borrow().contains_key(&n.id()) {
                continue;
            }
            let mut cursor = n.walk();
            if children_done {
                let memo = self.0.borrow();
                let answer = pred(&n)
                    || n.children(&mut cursor)
                        .any(|c| memo.get(&c.id()).copied().unwrap_or(false));
                drop(memo);
                self.0.borrow_mut().insert(n.id(), answer);
            } else {
                stack.push((n, true));
                let memo = self.0.borrow();
                let pending: Vec<Node> = n
                    .children(&mut cursor)
                    .filter(|c| !memo.contains_key(&c.id()))
                    .collect();
                drop(memo);
                stack.extend(pending.into_iter().map(|c| (c, false)));
            }
        }
        self.0.borrow()[&node.id()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lang_parsing_substrate::query;

    fn parse(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        parser.parse(code, None).unwrap()
    }

    #[test]
    fn answers_as_a_search_of_the_subtree_does_at_every_node() {
        let code = "int f(unsigned a, int b) { return (a + (int)b) * g(1u, b) - (b << 2); }\n\
                    int h(void) { size_t s = sizeof(unsigned long); return s + 1; }\n";
        let tree = parse(code);
        let memo = SubtreeAny::default();
        let unsigned_word = |n: &Node| {
            matches!(n.kind(), "primitive_type" | "sized_type_specifier")
                && n.utf8_text(code.as_bytes()).unwrap().contains("unsigned")
        };
        // Asked of every node, inner ones after outer ones and the reverse.
        let mut all = query::find_descendants(tree.root_node(), |_| true);
        for pass in 0..2 {
            for n in &all {
                assert_eq!(
                    memo.any(n, unsigned_word),
                    !query::find_descendants(*n, |m| unsigned_word(&m)).is_empty(),
                    "pass {pass}: {}",
                    n.kind()
                );
            }
            all.reverse();
            memo.clear();
        }
    }

    #[test]
    fn a_deep_sum_is_answered_without_a_deep_call_stack() {
        let code = format!("int f(int x) {{ return {}x; }}\n", "x + ".repeat(20_000));
        let tree = parse(&code);
        let identifiers = SubtreeAny::default();
        let calls = SubtreeAny::default();
        assert!(identifiers.any(&tree.root_node(), |n| n.kind() == "identifier"));
        assert!(!calls.any(&tree.root_node(), |n| n.kind() == "call_expression"));
    }
}
