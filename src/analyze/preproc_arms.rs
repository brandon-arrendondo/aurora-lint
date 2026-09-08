//! Which byte offsets a preprocessor conditional puts in MUTUALLY EXCLUSIVE
//! arms.
//!
//! aurora-lint does not preprocess, so tree-sitter parses BOTH arms of an
//! `#ifdef`/`#else` and a name declared once per arm becomes one name whose
//! recorded history interleaves two lifetimes that cannot both exist. Any
//! analysis that answers "what did this name hold at byte P" by reading
//! backwards through the file therefore has to know that a record in the other
//! arm is not a record at all -- hostap's `wpa_driver_ndis_get_names` declares
//! `pos` once per arm, and the `#ifdef` arm's `pos = (WCHAR *) (b + off)` was
//! answering queries in the `#else` arm's `pos - names`.
//!
//! This is the OPPOSITE stance to
//! `ast_utils::collect_declarations_transparent_to_preproc`, and deliberately:
//! a declaration in EITHER arm is a declaration, so a search for one should
//! look through the fork. The fact wanted here is narrower and positive --
//! these two offsets sit in DIFFERENT arms of one conditional, so no single
//! translation unit contains both.

use lang_parsing_substrate::query;
use std::ops::Range;
use tree_sitter::Node;

/// One arm of one conditional chain: which chain, and which of its arms.
type ArmId = (u32, u32);

/// The preprocessor branch structure of one translation unit, indexed for
/// point queries.
///
/// Built as a partition of the file into regions whose enclosing arms do not
/// change, each carrying the arms that enclose it, innermost last. Answering
/// is then a binary search plus a walk over two short lists -- the nesting
/// depth of `#if`s, not the number of them, which is what keeps a file with
/// hundreds of conditionals from costing a linear scan on every lookup.
#[derive(Clone, Debug, Default)]
pub struct PreprocArms {
    /// Region boundaries, ascending. Region `i` spans
    /// `boundaries[i]..boundaries[i + 1]`.
    boundaries: Vec<usize>,
    /// The arms enclosing each region, sorted by chain id. One entry per
    /// region, so `paths.len() + 1 == boundaries.len()` whenever either is
    /// non-empty.
    paths: Vec<Vec<ArmId>>,
}

impl PreprocArms {
    /// Read every conditional chain under `root`.
    ///
    /// A chain is headed by `preproc_if`/`preproc_ifdef` and linked by the
    /// `alternative` field through its `#elif`/`#elifdef`/`#else` arms. A
    /// chain nested inside an arm is collected as its own entry, which is what
    /// makes the answer compositional: two offsets are exclusive if ANY chain
    /// splits them, at whatever depth.
    ///
    /// A chain with no alternative is dropped: `#ifdef X ... #endif` puts
    /// nothing in a second arm, so it can never separate two offsets.
    pub fn collect(root: &Node) -> Self {
        let mut arms: Vec<(Range<usize>, ArmId)> = Vec::new();
        let mut chain_id: u32 = 0;
        for head in query::find_descendants_of_kinds(*root, &["preproc_if", "preproc_ifdef"]) {
            let mut spans: Vec<Range<usize>> = Vec::new();
            let mut start = head.start_byte();
            let mut current = head;
            loop {
                match current.child_by_field_name("alternative") {
                    Some(alternative) => {
                        spans.push(start..alternative.start_byte());
                        start = alternative.start_byte();
                        current = alternative;
                    }
                    None => {
                        spans.push(start..current.end_byte());
                        break;
                    }
                }
            }
            if spans.len() < 2 {
                continue;
            }
            for (index, span) in spans.into_iter().enumerate() {
                arms.push((span, (chain_id, index as u32)));
            }
            chain_id += 1;
        }
        if arms.is_empty() {
            return Self::default();
        }

        let mut boundaries: Vec<usize> = arms
            .iter()
            .flat_map(|(span, _)| [span.start, span.end])
            .collect();
        boundaries.sort_unstable();
        boundaries.dedup();

        let paths = boundaries
            .windows(2)
            .map(|edges| {
                // Any point inside the region has the same enclosing arms, and
                // a region never straddles a boundary, so one probe decides it.
                let probe = edges[0];
                let mut enclosing: Vec<ArmId> = arms
                    .iter()
                    .filter(|(span, _)| span.contains(&probe))
                    .map(|(_, id)| *id)
                    .collect();
                enclosing.sort_unstable();
                enclosing
            })
            .collect();

        Self { boundaries, paths }
    }

    /// Whether some conditional puts `a` and `b` in two different arms.
    ///
    /// False whenever either offset is outside every chain, which is the
    /// answer that keeps this positive-only: an offset above the `#if` or
    /// below the `#endif` coexists with both arms.
    pub fn exclusive(&self, a: usize, b: usize) -> bool {
        if self.paths.is_empty() {
            return false;
        }
        let (Some(first), Some(second)) = (self.path_at(a), self.path_at(b)) else {
            return false;
        };
        // Both lists are sorted by chain id, so one merge walk finds every
        // chain they share and stops at the first that splits them.
        let (mut i, mut j) = (0, 0);
        while i < first.len() && j < second.len() {
            let ((left_chain, left_arm), (right_chain, right_arm)) = (first[i], second[j]);
            match left_chain.cmp(&right_chain) {
                std::cmp::Ordering::Less => i += 1,
                std::cmp::Ordering::Greater => j += 1,
                std::cmp::Ordering::Equal => {
                    if left_arm != right_arm {
                        return true;
                    }
                    i += 1;
                    j += 1;
                }
            }
        }
        false
    }

    /// The arms enclosing `pos`, or `None` when it falls outside every chain.
    fn path_at(&self, pos: usize) -> Option<&[ArmId]> {
        let region = self.boundaries.partition_point(|edge| *edge <= pos);
        // `paths` is one shorter than `boundaries`, so an offset at or past
        // the last boundary indexes off the end and reads as outside -- which
        // it is: the final boundary is the last `#endif`.
        let path = self.paths.get(region.checked_sub(1)?)?;
        if path.is_empty() {
            None
        } else {
            Some(path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::c_language;

    fn arms_of(source: &str) -> PreprocArms {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        PreprocArms::collect(&tree.root_node())
    }

    fn at(source: &str, needle: &str) -> usize {
        source.find(needle).expect("needle present in fixture")
    }

    #[test]
    fn two_arms_of_one_ifdef_are_exclusive() {
        let source = "void f(void)\n{\n#ifdef A\n\tint x = 1;\n#else\n\tint y = 2;\n#endif\n}\n";
        let arms = arms_of(source);
        assert!(arms.exclusive(at(source, "int x"), at(source, "int y")));
    }

    #[test]
    fn one_arm_is_not_exclusive_with_itself() {
        let source = "void f(void)\n{\n#ifdef A\n\tint x = 1;\n\tint z = x;\n#else\n\tint y = 2;\n#endif\n}\n";
        let arms = arms_of(source);
        assert!(!arms.exclusive(at(source, "int x"), at(source, "int z")));
    }

    #[test]
    fn code_outside_the_chain_coexists_with_both_arms() {
        let source = "void f(void)\n{\n\tint w = 0;\n#ifdef A\n\tint x = 1;\n#else\n\tint y = 2;\n#endif\n}\n";
        let arms = arms_of(source);
        assert!(!arms.exclusive(at(source, "int w"), at(source, "int x")));
        assert!(!arms.exclusive(at(source, "int w"), at(source, "int y")));
    }

    #[test]
    fn an_elif_arm_is_exclusive_with_both_of_its_neighbours() {
        let source = "void f(void)\n{\n#if A\n\tint x = 1;\n#elif B\n\tint y = 2;\n#else\n\tint z = 3;\n#endif\n}\n";
        let arms = arms_of(source);
        assert!(arms.exclusive(at(source, "int x"), at(source, "int y")));
        assert!(arms.exclusive(at(source, "int y"), at(source, "int z")));
        assert!(arms.exclusive(at(source, "int x"), at(source, "int z")));
    }

    #[test]
    fn a_chain_with_no_else_never_separates_anything() {
        let source = "void f(void)\n{\n#ifdef A\n\tint x = 1;\n#endif\n\tint y = 2;\n}\n";
        let arms = arms_of(source);
        assert!(!arms.exclusive(at(source, "int x"), at(source, "int y")));
    }

    #[test]
    fn code_after_the_last_endif_coexists_with_both_arms() {
        let source = "void f(void)\n{\n#ifdef A\n\tint x = 1;\n#else\n\tint y = 2;\n#endif\n\tint w = 0;\n}\n";
        let arms = arms_of(source);
        assert!(!arms.exclusive(at(source, "int w"), at(source, "int x")));
        assert!(!arms.exclusive(at(source, "int w"), at(source, "int y")));
    }

    #[test]
    fn two_sequential_chains_do_not_separate_their_first_arms() {
        let source = concat!(
            "void f(void)\n{\n#ifdef A\n\tint x = 1;\n#else\n\tint p = 0;\n#endif\n",
            "#ifdef B\n\tint y = 2;\n#else\n\tint q = 0;\n#endif\n}\n"
        );
        let arms = arms_of(source);
        assert!(!arms.exclusive(at(source, "int x"), at(source, "int y")));
        assert!(arms.exclusive(at(source, "int x"), at(source, "int p")));
        assert!(arms.exclusive(at(source, "int y"), at(source, "int q")));
    }

    #[test]
    fn a_nested_chain_splits_within_an_arm() {
        let source = concat!(
            "void f(void)\n{\n#ifdef A\n",
            "#ifdef B\n\tint x = 1;\n#else\n\tint y = 2;\n#endif\n",
            "#else\n\tint z = 3;\n#endif\n}\n"
        );
        let arms = arms_of(source);
        assert!(arms.exclusive(at(source, "int x"), at(source, "int y")));
        assert!(arms.exclusive(at(source, "int x"), at(source, "int z")));
        assert!(arms.exclusive(at(source, "int y"), at(source, "int z")));
    }
}
