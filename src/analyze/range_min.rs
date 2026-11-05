//! The least of a list's values over any range, for the pre-parse repair
//! passes that ask whether a run of lines keeps its brackets balanced: a
//! run does when it ends at the depth it starts at and no line of it goes
//! below. Asked once per block of a nest, a scan of each block is quadratic
//! in the nest's depth; this answers each in time logarithmic in the file's
//! length, from a table twice its length.

/// A segment tree over `i32` values, built once.
pub(crate) struct MinTree {
    len: usize,
    tree: Vec<i32>,
}

impl MinTree {
    pub(crate) fn new(values: &[i32]) -> MinTree {
        let len = values.len();
        let mut tree = vec![i32::MAX; 2 * len];
        tree[len..].copy_from_slice(values);
        for k in (1..len).rev() {
            tree[k] = tree[2 * k].min(tree[2 * k + 1]);
        }
        MinTree { len, tree }
    }

    /// The least value at `range`, or `i32::MAX` for an empty one.
    pub(crate) fn min(&self, range: std::ops::Range<usize>) -> i32 {
        let (mut l, mut r) = (range.start + self.len, range.end + self.len);
        let mut least = i32::MAX;
        while l < r {
            if l % 2 == 1 {
                least = least.min(self.tree[l]);
                l += 1;
            }
            if r % 2 == 1 {
                r -= 1;
                least = least.min(self.tree[r]);
            }
            l /= 2;
            r /= 2;
        }
        least
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_range_gets_the_least_of_its_values() {
        for len in 0..=17usize {
            let values: Vec<i32> = (0..len).map(|k| ((k * 7919) % 13) as i32 - 6).collect();
            let tree = MinTree::new(&values);
            for a in 0..=len {
                for b in a..=len {
                    let expected = values[a..b].iter().copied().min().unwrap_or(i32::MAX);
                    assert_eq!(tree.min(a..b), expected, "{values:?} {a}..{b}");
                }
            }
        }
    }
}
