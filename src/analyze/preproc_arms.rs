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

/// One conditional arm enclosing a node: the chain's `#if`/`#ifdef`, and the
/// arm's place in that chain (0 for the `#if`'s own).
#[derive(Clone, Copy, Debug)]
pub struct EnclosingArm<'t> {
    /// The `preproc_if` or `preproc_ifdef` opening the chain.
    pub head: Node<'t>,
    /// The arm's place in the chain, 0 for the `#if`'s own.
    pub index: u32,
}

/// The arms enclosing `node`, outermost first. A chain with no alternative
/// counts too: `#ifdef X ... #endif` still holds its body.
pub fn enclosing_arms<'t>(node: &Node<'t>) -> Vec<EnclosingArm<'t>> {
    let mut arms = Vec::new();
    let mut from = *node;
    while let Some(parent) = from.parent() {
        let is_arm = matches!(
            parent.kind(),
            "preproc_if" | "preproc_ifdef" | "preproc_elif" | "preproc_elifdef" | "preproc_else"
        );
        let through_alternative = parent
            .child_by_field_name("alternative")
            .is_some_and(|alternative| alternative.id() == from.id());
        if !is_arm || through_alternative {
            from = parent;
            continue;
        }
        let mut head = parent;
        let mut index = 0;
        while matches!(
            head.kind(),
            "preproc_elif" | "preproc_elifdef" | "preproc_else"
        ) {
            let Some(previous) = head.parent() else {
                break;
            };
            head = previous;
            index += 1;
        }
        arms.push(EnclosingArm { head, index });
        from = head;
    }
    arms.reverse();
    arms
}

/// The chain's opening directive as written, `#ifdef A` or `#if A > 1`: two
/// chains opened by the same text ask the same question.
fn opening_directive<'s>(head: &Node, source: &'s str) -> Option<&'s str> {
    let condition = head
        .child_by_field_name("condition")
        .or_else(|| head.child_by_field_name("name"))?;
    source.get(head.start_byte()..condition.end_byte())
}

/// The names a condition's text mentions, `defined` aside.
fn names_in(condition: &str) -> impl Iterator<Item = &str> {
    condition
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|word| {
            word.chars().next().is_some_and(|c| !c.is_ascii_digit()) && *word != "defined"
        })
}

/// The names the conditions of every arm of the chain opened by `head` read.
pub fn chain_condition_names<'s>(head: &Node, source: &'s str) -> Vec<&'s str> {
    let mut names = Vec::new();
    let mut arm = Some(*head);
    while let Some(current) = arm {
        let condition = current
            .child_by_field_name("condition")
            .or_else(|| current.child_by_field_name("name"));
        if let Some(text) = condition.and_then(|c| source.get(c.byte_range())) {
            names.extend(names_in(text));
        }
        arm = current.child_by_field_name("alternative");
    }
    names
}

/// Whether a `#define` or `#undef` line in `text` names one of `names`.
fn redefines_any(text: &str, names: &[&str]) -> bool {
    text.lines().any(|line| {
        let Some(directive) = line.trim_start().strip_prefix('#') else {
            return false;
        };
        let directive = directive.trim_start();
        let Some(rest) = directive
            .strip_prefix("define")
            .or_else(|| directive.strip_prefix("undef"))
        else {
            return false;
        };
        names_in(rest).next().is_some_and(|n| names.contains(&n))
    })
}

/// Whether the chains opened by `a` and `b` read a macro in common that the
/// file does not define or undefine between them, so that their arms do not
/// vary independently.
pub fn chains_read_one_macro(a: &Node, b: &Node, source: &str) -> bool {
    let theirs = chain_condition_names(b, source);
    let shared: Vec<&str> = chain_condition_names(a, source)
        .into_iter()
        .filter(|name| theirs.contains(name))
        .collect();
    let first = a.start_byte().min(b.start_byte());
    let second = a.start_byte().max(b.start_byte());
    shared.iter().any(|name| {
        !source
            .get(first..second)
            .is_none_or(|between| redefines_any(between, std::slice::from_ref(name)))
    })
}

/// Whether the file defines or undefines a macro the chain opened by `head`
/// reads, before that chain.
pub fn chain_reads_macro_set_above(head: &Node, source: &str) -> bool {
    let names = chain_condition_names(head, source);
    source
        .get(..head.start_byte())
        .is_some_and(|above| redefines_any(above, &names))
}

/// Whether no configuration compiles both `a` and `b`: one chain puts them in
/// different arms, or two chains opened by the same directive put one in the
/// opening arm and the other past it (`#if A` ... `#else` ... `#endif`, then
/// `#if A` again). The second holds only if the file defines or undefines no
/// name of that directive from the first chain's start to the second's, so an
/// include guard's own `#define` does not make its `#ifndef` two questions
/// with one answer. An `#include` between them is not looked into. Nor
/// does it hold for one chain inside the other: a brace opened in one arm
/// and closed in another leads the parser to nest chains that follow one
/// another, the outer chain's opening arm running on over the inner chain.
/// Positive-only, like [`PreprocArms::exclusive`], and for a caller with
/// nodes in hand and no reason to index the whole file.
pub fn never_compile_together(a: &Node, b: &Node, source: &str) -> bool {
    let theirs = enclosing_arms(b);
    enclosing_arms(a).iter().any(|ours| {
        theirs.iter().any(|other| {
            if ours.head.id() == other.head.id() {
                return ours.index != other.index;
            }
            if (ours.index == 0) == (other.index == 0) {
                return false;
            }
            let in_sequence = ours.head.end_byte() <= other.head.start_byte()
                || other.head.end_byte() <= ours.head.start_byte();
            if !in_sequence {
                return false;
            }
            let Some(directive) = opening_directive(&ours.head, source) else {
                return false;
            };
            if opening_directive(&other.head, source) != Some(directive) {
                return false;
            }
            let first = ours.head.start_byte().min(other.head.start_byte());
            let second = ours.head.start_byte().max(other.head.start_byte());
            let names: Vec<&str> = names_in(directive.trim_start_matches('#'))
                .filter(|n| !matches!(*n, "if" | "ifdef" | "ifndef"))
                .collect();
            !source
                .get(first..second)
                .is_none_or(|between| redefines_any(between, &names))
        })
    })
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

    /// `never_compile_together` of the identifiers `a` and `b` in `source`.
    fn apart(source: &str) -> bool {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        let node = |needle: &str| {
            let at = at(source, needle);
            root.descendant_for_byte_range(at, at + 1).unwrap()
        };
        never_compile_together(&node("int a"), &node("int b"), source)
    }

    #[test]
    fn arms_of_one_chain_never_compile_together() {
        assert!(apart("#if X\nint a;\n#else\nint b;\n#endif\n"));
        assert!(apart("#if X\nint a;\n#elif Y\nint b;\n#endif\n"));
        assert!(!apart("#if X\nint a;\nint b;\n#endif\n"));
    }

    #[test]
    fn a_repeated_condition_is_read_as_one_chain() {
        assert!(apart(
            "#if X\nint a;\n#else\nint c;\n#endif\n#if X\nint d;\n#else\nint b;\n#endif\n"
        ));
        assert!(!apart(
            "#if X\nint a;\n#else\nint c;\n#endif\n#if X\nint b;\n#else\nint d;\n#endif\n"
        ));
        assert!(!apart(
            "#if X\nint a;\n#else\nint c;\n#endif\n#if Y\nint d;\n#else\nint b;\n#endif\n"
        ));
        // Past the opening arm in both: `#elif`s of unknown relation.
        assert!(!apart(
            "#if X\n#elif Y\nint a;\n#endif\n#if X\n#elif Z\nint b;\n#endif\n"
        ));
        // One chain inside the other's opening arm is not a second asking.
        assert!(!apart(
            "#if X\nint a;\n#if X\n#else\nint b;\n#endif\n#endif\n"
        ));
    }

    #[test]
    fn a_macro_redefined_between_two_chains_splits_nothing() {
        assert!(!apart(
            "#if X\nint a;\n#endif\n#undef X\n#if X\n#else\nint b;\n#endif\n"
        ));
        assert!(!apart(
            "#if X\nint a;\n#endif\n#define X 0\n#if X\n#else\nint b;\n#endif\n"
        ));
        // An include guard defines its own name inside the first chain.
        assert!(!apart(
            "#ifndef X\n#define X\nint a;\n#endif\n#ifndef X\n#else\nint b;\n#endif\n"
        ));
        // Every name of a compound condition counts; another name changes nothing.
        assert!(!apart(
            "#if X && Y\nint a;\n#endif\n#define Y 0\n#if X && Y\n#else\nint b;\n#endif\n"
        ));
        assert!(apart(
            "#if X\nint a;\n#endif\n#define Z 0\n#if X\n#else\nint b;\n#endif\n"
        ));
    }

    #[test]
    fn a_chain_reads_the_names_of_every_arm() {
        let source = "#if X > 1 && defined(Y)\n#elif Z\n#else\n#endif\n";
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let head = tree.root_node().named_child(0).unwrap();
        assert_eq!(chain_condition_names(&head, source), ["X", "Y", "Z"]);
    }

    #[test]
    fn chains_read_one_macro_unless_it_changes_between_them() {
        let read = |source: &str| {
            let mut parser = tree_sitter::Parser::new();
            parser.set_language(&c_language()).unwrap();
            let tree = parser.parse(source, None).unwrap();
            let heads = query::find_descendants_of_kinds(
                tree.root_node(),
                &["preproc_if", "preproc_ifdef"],
            );
            chains_read_one_macro(&heads[0], &heads[1], source)
        };
        assert!(read("#ifdef X\n#endif\n#if defined(X) && Y\n#endif\n"));
        assert!(!read("#ifdef X\n#endif\n#ifdef Y\n#endif\n"));
        assert!(!read("#ifdef X\n#endif\n#undef X\n#ifdef X\n#endif\n"));
    }

    #[test]
    fn outside_every_arm_compiles_with_any() {
        assert!(!apart("int a;\n#if X\nint b;\n#endif\n"));
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
