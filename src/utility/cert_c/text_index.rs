//! A file's text, read once, for the substring questions a rule asks of many
//! nodes' text.
//!
//! `get_node_text(n).contains(p)` and
//! `get_sanitized_node_text(n).contains(p)` cost the length of `n`'s text,
//! and sanitizing costs a walk of `n`'s subtree on top. A rule that asks at
//! every operator of an expression, of the operator's own text or of its
//! whole enclosing function's, pays the square of the expression's length.
//!
//! [`TextIndex`] keeps the file's text (sanitized, if asked) once, so a
//! node's text is a slice of it, and remembers where each pattern occurs,
//! so "does this span contain `p`" is a binary search. The answers are the
//! ones the per-node forms give: sanitizing blanks comment and literal
//! nodes in place, byte for byte, and every such node inside a node's span
//! is a node of its subtree, so the slice of the sanitized file is the
//! node's own sanitized text.

use std::cell::RefCell;
use std::collections::HashMap;

use lang_parsing_substrate::query;
use tree_sitter::Node;

/// One file's text and where each pattern asked about occurs in it.
pub struct TextIndex {
    text: String,
    /// Every start offset of each pattern asked about, overlapping ones
    /// included, ascending.
    occurrences: RefCell<HashMap<String, Vec<usize>>>,
}

impl TextIndex {
    /// The file's text as written.
    pub fn raw(source: &str) -> Self {
        Self::of(source.to_string())
    }

    /// The text of the file `root` was parsed from with every comment,
    /// string literal and character literal blanked as
    /// [`get_sanitized_node_text`](super::ast_utils::get_sanitized_node_text)
    /// blanks them: spaces for every byte but a newline.
    pub fn sanitized(root: &Node, source: &str) -> Self {
        Self::blanking(root, source, |n| {
            matches!(n.kind(), "comment" | "string_literal" | "char_literal")
        })
    }

    /// The text of the file `root` was parsed from with the span of every
    /// node `blank` accepts turned to spaces, newlines kept, so every offset
    /// still means what it meant in the source. What to blank is the
    /// caller's, and so is the language.
    pub fn blanking(root: &Node, source: &str, blank: impl Fn(&Node) -> bool) -> Self {
        let start = root.start_byte();
        let end = root.end_byte();
        let mut bytes = source.as_bytes().to_vec();
        for node in query::find_descendants(*root, |n| blank(&n)) {
            let from = node.start_byte().max(start);
            let to = node.end_byte().min(end).max(from);
            for b in &mut bytes[from..to] {
                if *b != b'\n' {
                    *b = b' ';
                }
            }
        }
        Self::of(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn of(text: String) -> Self {
        Self {
            text,
            occurrences: RefCell::new(HashMap::new()),
        }
    }

    /// `node`'s text in this index: its sanitized text for an index built
    /// with [`TextIndex::sanitized`].
    pub fn text(&self, node: &Node) -> &str {
        &self.text[node.start_byte()..node.end_byte()]
    }

    /// The text from `start` to `end`.
    pub fn span(&self, start: usize, end: usize) -> &str {
        &self.text[start..end]
    }

    /// Whether `node`'s text contains `pattern`: `self.text(node).contains(pattern)`.
    pub fn contains(&self, node: &Node, pattern: &str) -> bool {
        self.span_contains(node.start_byte(), node.end_byte(), pattern)
    }

    /// Whether the text from `start` to `end` contains `pattern`.
    pub fn span_contains(&self, start: usize, end: usize, pattern: &str) -> bool {
        if pattern.is_empty() {
            return true;
        }
        if end < start + pattern.len() {
            return false;
        }
        let mut occurrences = self.occurrences.borrow_mut();
        let at = occurrences
            .entry(pattern.to_string())
            .or_insert_with(|| all_occurrences(&self.text, pattern));
        let first = at.partition_point(|&s| s < start);
        at.get(first).is_some_and(|&s| s + pattern.len() <= end)
    }
}

/// Every offset `pattern` starts at in `text`, overlapping occurrences
/// included (`str::match_indices` skips those, and the only occurrence
/// inside a span can be one that overlaps another).
fn all_occurrences(text: &str, pattern: &str) -> Vec<usize> {
    let step = pattern.chars().next().map_or(1, char::len_utf8);
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(found) = text[from..].find(pattern) {
        out.push(from + found);
        from += found + step;
        if from > text.len() {
            break;
        }
    }
    out
}
