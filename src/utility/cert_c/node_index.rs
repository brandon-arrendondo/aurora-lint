//! A tree's nodes in one table, read once, for the questions a climb out of
//! a node answers: its parent, its ancestors, and the nearest ancestor of a
//! kind.
//!
//! tree-sitter keeps no parent links. `Node::parent` finds a node's parent
//! by descending from the root, so a climb of `d` levels costs `O(d²)`, and
//! even one descent from the root ([`super::ast_utils::ancestors_from_root`])
//! costs the node's depth. A rule that asks about every node of a nesting
//! thousands of levels deep pays the square of the depth either way.
//!
//! [`NodeIndex`] walks the tree once, in pre-order, and records each node's
//! row and its parent's row. A parent is then a lookup, an ancestor chain
//! costs its own length, and [`NodeIndex::nearest_column`] answers "the
//! nearest ancestor where P" for every node in one more pass, so a walk
//! that wants only the statements or the scopes around a node can step
//! from one to the next without visiting the expressions in between.
//!
//! The index costs a few machine words per node, so a caller builds one
//! per tree it asks many such questions of, and holds it no longer than the
//! tree. Nothing here is specific to C.

use std::collections::HashMap;

use tree_sitter::Node;

/// The row of a node with no parent.
const NONE: u32 = u32::MAX;

/// Every node of one tree in pre-order, with each one's parent.
pub struct NodeIndex<'t> {
    nodes: Vec<Node<'t>>,
    /// Each row's parent's row, `NONE` for the root.
    parent: Vec<u32>,
    /// One past each row's last descendant: a node's subtree is the rows
    /// from its own up to this one.
    end: Vec<u32>,
    /// Each node's row, by `Node::id`.
    rows: HashMap<usize, u32>,
}

/// For every row of one [`NodeIndex`], the row of the nearest node at or
/// above it that a predicate accepts (`NONE` when none does).
pub struct NearestColumn(Vec<u32>);

impl<'t> NodeIndex<'t> {
    /// Index the tree under `root`, every node named or not, in one walk
    /// with a cursor (no recursion, so any depth).
    pub fn new(root: Node<'t>) -> Self {
        #[cfg(test)]
        BUILDS.with(|n| n.set(n.get() + 1));
        let mut index = Self {
            nodes: Vec::new(),
            parent: Vec::new(),
            end: Vec::new(),
            rows: HashMap::new(),
        };
        let mut cursor = root.walk();
        // The rows of the nodes on the cursor's path, outermost first.
        let mut open: Vec<u32> = Vec::new();
        loop {
            let node = cursor.node();
            let row = index.nodes.len() as u32;
            index.nodes.push(node);
            index.parent.push(open.last().copied().unwrap_or(NONE));
            index.end.push(row + 1);
            index.rows.insert(node.id(), row);
            if cursor.goto_first_child() {
                open.push(row);
                continue;
            }
            // A leaf: close it, then every ancestor whose last child it was.
            let mut closed = row;
            loop {
                index.end[closed as usize] = index.nodes.len() as u32;
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return index;
                }
                closed = open.pop().expect("the cursor's parent is open");
            }
        }
    }

    /// How many nodes the tree holds.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the tree holds no node (never, for a tree tree-sitter built).
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The tree's root.
    pub fn root(&self) -> Node<'t> {
        self.nodes[0]
    }

    /// `node`'s row, when `node` is in this tree.
    pub fn row(&self, node: &Node) -> Option<usize> {
        self.rows.get(&node.id()).map(|&r| r as usize)
    }

    /// The node in `row`.
    pub fn node(&self, row: usize) -> Node<'t> {
        self.nodes[row]
    }

    /// `node`'s parent: what `Node::parent` gives, in constant time. `None`
    /// for the root, and for a node of another tree.
    pub fn parent(&self, node: &Node) -> Option<Node<'t>> {
        let row = self.row(node)?;
        self.parent_row(row).map(|p| self.nodes[p])
    }

    /// `node`'s parent from the table when the table has it, else from
    /// `Node::parent`: for the indexed subtree's own top (whose parent lies
    /// outside it) and for a node of another tree. Always what
    /// `Node::parent` gives, so an index over just the subtree a caller
    /// walks serves every node it meets.
    pub fn parent_or_climb(&self, node: &Node<'t>) -> Option<Node<'t>> {
        self.parent(node).or_else(|| node.parent())
    }

    fn parent_row(&self, row: usize) -> Option<usize> {
        match self.parent[row] {
            NONE => None,
            p => Some(p as usize),
        }
    }

    /// `node`'s ancestors, innermost first and ending at the root: the
    /// nodes a `Node::parent` climb visits, at constant cost a step. Empty
    /// for a node of another tree.
    pub fn ancestors(&self, node: &Node) -> impl Iterator<Item = Node<'t>> + '_ {
        let mut row = self.row(node).and_then(|r| self.parent_row(r));
        std::iter::from_fn(move || {
            let current = row?;
            row = self.parent_row(current);
            Some(self.nodes[current])
        })
    }

    /// [`NodeIndex::ancestors`] for a node of this tree; for a node of
    /// another (a macro expansion parsed on its own, say), the climb with
    /// `Node::parent` the caller would otherwise make. The same nodes.
    pub fn ancestors_or_climb<'n>(
        &'n self,
        node: &Node<'t>,
    ) -> Box<dyn Iterator<Item = Node<'t>> + 'n> {
        if self.row(node).is_some() {
            Box::new(self.ancestors(node))
        } else {
            Box::new(std::iter::successors(node.parent(), |n| n.parent()))
        }
    }

    /// Whether `node` is `ancestor` or lies under it, in constant time.
    /// False when either is of another tree.
    pub fn contains(&self, ancestor: &Node, node: &Node) -> bool {
        match (self.row(ancestor), self.row(node)) {
            (Some(a), Some(n)) => a <= n && n < self.end[a] as usize,
            _ => false,
        }
    }

    /// For every node, the nearest node at or above it that `pred`
    /// accepts, worked out in one pass over the table: a node's answer is
    /// its own row when `pred` accepts it, else its parent's answer, and a
    /// parent's row comes before its children's.
    pub fn nearest_column(&self, pred: impl Fn(&Node<'t>) -> bool) -> NearestColumn {
        let mut nearest = Vec::with_capacity(self.nodes.len());
        for (row, node) in self.nodes.iter().enumerate() {
            let answer = if pred(node) {
                row as u32
            } else {
                match self.parent[row] {
                    NONE => NONE,
                    p => nearest[p as usize],
                }
            };
            nearest.push(answer);
        }
        NearestColumn(nearest)
    }

    /// The nearest node at or above `node` that `column`'s predicate
    /// accepts. `None` when none does, or `node` is of another tree.
    pub fn nearest(&self, column: &NearestColumn, node: &Node) -> Option<Node<'t>> {
        self.nearest_row(column, self.row(node)?)
            .map(|r| self.nodes[r])
    }

    /// The nearest node strictly above `node` that `column`'s predicate
    /// accepts: `node` itself does not count.
    pub fn nearest_above(&self, column: &NearestColumn, node: &Node) -> Option<Node<'t>> {
        let parent = self.parent_row(self.row(node)?)?;
        self.nearest_row(column, parent).map(|r| self.nodes[r])
    }

    /// Every node strictly above `node` that `column`'s predicate accepts,
    /// innermost first: the ancestors a climb filtered by the predicate
    /// keeps, at constant cost each, never visiting the ones in between.
    pub fn ancestors_where<'i>(
        &'i self,
        column: &'i NearestColumn,
        node: &Node,
    ) -> impl Iterator<Item = Node<'t>> + 'i {
        let mut row = self
            .row(node)
            .and_then(|r| self.parent_row(r))
            .and_then(|p| self.nearest_row(column, p));
        std::iter::from_fn(move || {
            let current = row?;
            row = self
                .parent_row(current)
                .and_then(|p| self.nearest_row(column, p));
            Some(self.nodes[current])
        })
    }

    fn nearest_row(&self, column: &NearestColumn, row: usize) -> Option<usize> {
        debug_assert_eq!(
            column.0.len(),
            self.nodes.len(),
            "a column of another index"
        );
        match column.0[row] {
            NONE => None,
            r => Some(r as usize),
        }
    }
}

#[cfg(test)]
thread_local! {
    /// How many indexes were built on this thread.
    static BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Indexes built on this thread since the last call.
#[cfg(test)]
pub(crate) fn take_builds() -> usize {
    BUILDS.with(|n| n.replace(0))
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

    const CODE: &str = "int f(int a) {\n  int b = a + (a * 2);\n  if (b) { for (int i = 0; i < b; i++) { b -= i; } }\n  return ({ int c = b; c; });\n}\n/* tail */ int g;\n";

    #[test]
    fn every_node_is_indexed_with_the_parent_and_ancestors_a_climb_finds() {
        let tree = parse(CODE);
        let index = NodeIndex::new(tree.root_node());
        let all = query::find_descendants(tree.root_node(), |_| true);
        assert_eq!(index.len(), all.len());
        assert_eq!(index.root().id(), tree.root_node().id());
        for node in &all {
            assert_eq!(
                index.parent(node).map(|p| p.id()),
                node.parent().map(|p| p.id()),
                "{}",
                node.kind()
            );
            let mut climbed = Vec::new();
            let mut n = *node;
            while let Some(p) = n.parent() {
                climbed.push(p.id());
                n = p;
            }
            let indexed: Vec<usize> = index.ancestors(node).map(|a| a.id()).collect();
            assert_eq!(indexed, climbed, "{}", node.kind());
        }
    }

    #[test]
    fn containment_and_nearest_answer_as_the_climb_does() {
        let tree = parse(CODE);
        let index = NodeIndex::new(tree.root_node());
        let all = query::find_descendants(tree.root_node(), |_| true);
        let is_scope = |n: &Node| matches!(n.kind(), "compound_statement" | "for_statement");
        let scopes = index.nearest_column(is_scope);
        for node in &all {
            let climb_nearest = std::iter::once(*node)
                .chain(index.ancestors(node))
                .find(is_scope)
                .map(|n| n.id());
            assert_eq!(index.nearest(&scopes, node).map(|n| n.id()), climb_nearest);
            let climb_above: Vec<usize> = index
                .ancestors(node)
                .filter(is_scope)
                .map(|n| n.id())
                .collect();
            assert_eq!(
                index.nearest_above(&scopes, node).map(|n| n.id()),
                climb_above.first().copied()
            );
            let jumped: Vec<usize> = index
                .ancestors_where(&scopes, node)
                .map(|n| n.id())
                .collect();
            assert_eq!(jumped, climb_above, "{}", node.kind());
            for other in &all {
                let under = std::iter::once(*other)
                    .chain(index.ancestors(other))
                    .any(|a| a.id() == node.id());
                assert_eq!(index.contains(node, other), under);
            }
        }
    }

    #[test]
    fn a_node_of_another_tree_is_not_indexed() {
        let tree = parse(CODE);
        let other = parse(CODE);
        let index = NodeIndex::new(tree.root_node());
        let stranger = other.root_node().child(0).unwrap();
        assert_eq!(index.row(&stranger), None);
        assert!(index.parent(&stranger).is_none());
        assert_eq!(index.ancestors(&stranger).count(), 0);
        assert!(!index.contains(&tree.root_node(), &stranger));
    }

    #[test]
    fn a_nesting_thousands_deep_is_indexed_without_a_deep_call_stack() {
        let depth = 20_000;
        let code = format!(
            "int f(int x) {{ return {}x{}; }}\n",
            "(".repeat(depth),
            ")".repeat(depth)
        );
        let tree = parse(&code);
        let index = NodeIndex::new(tree.root_node());
        let deepest = query::find_descendants(tree.root_node(), |n| n.kind() == "identifier")
            .into_iter()
            .last()
            .unwrap();
        assert!(index.ancestors(&deepest).count() > depth);
        let functions = index.nearest_column(|n| n.kind() == "function_definition");
        assert_eq!(
            index.nearest(&functions, &deepest).map(|f| f.kind()),
            Some("function_definition")
        );
    }
}
