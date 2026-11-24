//! The identity of a source text, for a per-thread memo keyed on the text it
//! was computed from.
//!
//! A buffer's address and length do not identify its text: once a buffer is
//! freed, another text of the same length may be allocated at the same
//! address, on the next file or on a snippet parsed on its own within one
//! file. A memo that compares only the address and length then answers for
//! the earlier text. [`SourceIdentity`] keeps a copy of the text and
//! compares it as well, so such a memo answers only for the text it read.

/// A source text, by its buffer's address and length and by its bytes.
#[derive(Debug, Clone)]
pub struct SourceIdentity {
    buffer: (usize, usize),
    text: Box<str>,
}

impl SourceIdentity {
    /// The identity of `source`.
    pub fn of(source: &str) -> Self {
        SourceIdentity {
            buffer: buffer_of(source),
            text: source.into(),
        }
    }

    /// Whether `source` is the text this identity was taken from, in the
    /// same buffer. A different address or length answers at once; the
    /// same ones compare the bytes.
    pub fn is(&self, source: &str) -> bool {
        self.buffer == buffer_of(source) && *self.text == *source
    }
}

fn buffer_of(source: &str) -> (usize, usize) {
    (source.as_ptr() as usize, source.len())
}

#[cfg(test)]
mod tests {
    use super::SourceIdentity;

    #[test]
    fn a_text_is_itself_and_another_text_of_its_length_is_not() {
        let first = String::from("int a = 1;");
        let identity = SourceIdentity::of(&first);
        assert!(identity.is(&first));
        let other = String::from("int b = 2;");
        assert!(!identity.is(&other));
        // The same bytes in the same buffer after a rewrite in place, as a
        // freed buffer reused for another text of its length is.
        let mut reused = first;
        reused.replace_range(4..5, "b");
        assert!(!identity.is(&reused));
    }
}
