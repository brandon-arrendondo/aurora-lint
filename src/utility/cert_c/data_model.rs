// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! The integer data model a scan credits: how wide each integer type is, what
//! the `<limits.h>` macros are, and how many bytes `sizeof` gives.
//!
//! Integer widths are implementation-defined (ADR-0011). Under [`DataModel::Iso`],
//! the default, only what ISO C guarantees is known: the minimum magnitudes of
//! C11 5.2.4.2.1 (`CHAR_BIT` at least 8, `short` and `int` at least 16 bits,
//! `long` at least 32, `long long` at least 64), the conversion-rank order
//! (6.3.1.1p1: a higher rank never has a smaller range), and the exact width
//! of an exact-width type such as `int32_t` (7.20.1.1). Anything wider
//! (`int` is 32 bits, `long` is 64) holds only on a model a project declares
//! (`[environment] data_model`), never because the benchmark corpora happen
//! to be built for one.
//!
//! So each question has two answers. A guaranteed one (`min_width`,
//! `guaranteed_range`) is what a proof that a value FITS may use: it holds on
//! every conforming implementation. An exact one (`exact_width`, `range`,
//! `limit_macro`, `sizeof_bytes`) is `None` unless the model fixes it, and a
//! caller must then treat the quantity as unknown in both directions.

use serde::{Deserialize, Serialize};

/// Integer conversion rank (C11 6.3.1.1), `Bool` lowest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rank {
    /// `_Bool`.
    Bool,
    /// The three `char` types.
    Char,
    /// `short`.
    Short,
    /// `int`.
    Int,
    /// `long`.
    Long,
    /// `long long`.
    LongLong,
}

/// What a data model knows about one integer type's width: its rank when
/// the model fixes it, the fewest bits it can have, and its exact width when
/// that is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntWidth {
    /// Its conversion rank, when the model fixes it.
    pub rank: Option<Rank>,
    /// The width every implementation gives it at least.
    pub min: u32,
    /// Its exact width, when the model fixes it.
    pub max: Option<u32>,
}

impl IntWidth {
    /// Whether this type may be narrower than `other` on some target the
    /// model allows. Never when it has the same or a higher rank (a higher
    /// rank never has a smaller range, C11 6.3.1.1p1) or is at least as wide
    /// as `other` can be; otherwise when its widths leave room.
    ///
    /// Two types the model describes identically (`size_t` and `size_t`)
    /// count as the same width.
    pub fn may_be_narrower_than(self, other: IntWidth) -> bool {
        if self == other {
            return false;
        }
        if let (Some(a), Some(b)) = (self.rank, other.rank) {
            if a >= b {
                return false;
            }
        }
        other.max.is_none_or(|o| self.min < o)
    }
}

/// The target's integer data model.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataModel {
    /// Only what ISO C guarantees; see the module documentation.
    #[default]
    Iso,
    /// `int`, `long` and pointers 32 bits (32-bit Linux and Windows).
    Ilp32,
    /// `int` 32 bits, `long` and pointers 64 (64-bit Linux, the BSDs, macOS).
    Lp64,
    /// `int` and `long` 32 bits, `long long` and pointers 64 (64-bit Windows).
    Llp64,
}

impl DataModel {
    /// The width in bits of an integer of `rank` when the model fixes it.
    /// `_Bool` holds exactly 0 and 1 on every model. Each declared model has
    /// an 8-bit `char`.
    pub fn exact_width(self, rank: Rank) -> Option<u32> {
        let long = match self {
            DataModel::Iso => return (rank == Rank::Bool).then_some(1),
            DataModel::Ilp32 | DataModel::Llp64 => 32,
            DataModel::Lp64 => 64,
        };
        Some(match rank {
            Rank::Bool => 1,
            Rank::Char => 8,
            Rank::Short => 16,
            Rank::Int => 32,
            Rank::Long => long,
            Rank::LongLong => 64,
        })
    }

    /// The width in bits every implementation gives an integer of `rank` at
    /// least (C11 5.2.4.2.1), or the exact width on a declared model.
    pub fn min_width(self, rank: Rank) -> u32 {
        self.exact_width(rank).unwrap_or(match rank {
            Rank::Bool => 1,
            Rank::Char => 8,
            Rank::Short | Rank::Int => 16,
            Rank::Long => 32,
            Rank::LongLong => 64,
        })
    }

    /// The exact range of an integer of `rank`, when the model fixes it.
    /// Signed types are two's complement on every declared model.
    pub fn range(self, signed: bool, rank: Rank) -> Option<(i128, i128)> {
        let width = self.exact_width(rank)?;
        Some(if rank == Rank::Bool {
            (0, 1)
        } else if signed {
            (-(1i128 << (width - 1)), (1i128 << (width - 1)) - 1)
        } else {
            (0, (1i128 << width) - 1)
        })
    }

    /// The range every implementation's integer of `rank` holds at least:
    /// every value in it is representable wherever the code is built (the
    /// C11 5.2.4.2.1 magnitudes, whose signed minimum is `-(2^(N-1) - 1)`),
    /// or the exact range on a declared model.
    pub fn guaranteed_range(self, signed: bool, rank: Rank) -> (i128, i128) {
        if let Some(range) = self.range(signed, rank) {
            return range;
        }
        let width = self.min_width(rank);
        if signed {
            (-((1i128 << (width - 1)) - 1), (1i128 << (width - 1)) - 1)
        } else {
            (0, (1i128 << width) - 1)
        }
    }

    /// What the model knows about the width of an integer of `rank`.
    pub fn width_of(self, rank: Rank) -> IntWidth {
        IntWidth {
            rank: Some(rank),
            min: self.min_width(rank),
            max: self.exact_width(rank),
        }
    }

    /// The signedness (`true` for unsigned) and width of the integer type a
    /// spelling names: a standard integer type in its usual spellings, an
    /// exact-width `<stdint.h>` type, or `size_t`, `ssize_t`, `ptrdiff_t`,
    /// `intptr_t` and `uintptr_t`. `None` for anything else: a typedef not
    /// yet followed, a struct, a pointer. Plain `char` answers "not
    /// unsigned" only in the sense that it is not declared so; whether it is
    /// signed is implementation-defined.
    pub fn spelled_width(self, spelling: &str) -> Option<(bool, IntWidth)> {
        let exact = |unsigned, bits: u32| {
            let rank = [
                Rank::Char,
                Rank::Short,
                Rank::Int,
                Rank::Long,
                Rank::LongLong,
            ]
            .into_iter()
            .find(|r| self.exact_width(*r) == Some(bits));
            Some((
                unsigned,
                IntWidth {
                    rank,
                    min: bits,
                    max: Some(bits),
                },
            ))
        };
        let word = |unsigned| {
            let rank = match self {
                DataModel::Iso => None,
                DataModel::Ilp32 => Some(Rank::Int),
                DataModel::Lp64 => Some(Rank::Long),
                DataModel::Llp64 => Some(Rank::LongLong),
            };
            Some((
                unsigned,
                IntWidth {
                    rank,
                    min: self.pointer_width().unwrap_or(16),
                    max: self.pointer_width(),
                },
            ))
        };
        let t = spelling.trim();
        let rank = match t {
            "char" | "signed char" | "unsigned char" => Rank::Char,
            "short" | "signed short" | "unsigned short" | "short int" | "signed short int"
            | "unsigned short int" => Rank::Short,
            "int" | "signed" | "unsigned" | "signed int" | "unsigned int" => Rank::Int,
            "long" | "signed long" | "unsigned long" | "long int" | "signed long int"
            | "unsigned long int" => Rank::Long,
            "long long"
            | "signed long long"
            | "unsigned long long"
            | "long long int"
            | "signed long long int"
            | "unsigned long long int" => Rank::LongLong,
            "int8_t" => return exact(false, 8),
            "uint8_t" => return exact(true, 8),
            "int16_t" => return exact(false, 16),
            "uint16_t" => return exact(true, 16),
            "int32_t" => return exact(false, 32),
            "uint32_t" => return exact(true, 32),
            "int64_t" => return exact(false, 64),
            "uint64_t" => return exact(true, 64),
            "ssize_t" | "ptrdiff_t" | "intptr_t" => return word(false),
            "size_t" | "uintptr_t" => return word(true),
            _ => return None,
        };
        Some((t.starts_with("unsigned"), self.width_of(rank)))
    }

    /// The width in bits of a pointer, or of `size_t`, `ptrdiff_t`,
    /// `intptr_t` and `uintptr_t`, when the model fixes it.
    pub fn pointer_width(self) -> Option<u32> {
        match self {
            DataModel::Iso => None,
            DataModel::Ilp32 => Some(32),
            DataModel::Lp64 | DataModel::Llp64 => Some(64),
        }
    }

    /// `sizeof` an integer of `rank`, in bytes, when the model fixes it. The
    /// `char` types are 1 by definition (C11 6.5.3.4p4).
    pub fn sizeof_bytes(self, rank: Rank) -> Option<u32> {
        match rank {
            Rank::Char => Some(1),
            Rank::Bool if self == DataModel::Iso => None,
            Rank::Bool => Some(1),
            _ => self.exact_width(rank).map(|w| w / 8),
        }
    }

    /// The value of a `<limits.h>` or `<stdint.h>` limit macro when it is
    /// fixed. The exact-width macros (`INT32_MAX`, `UINT8_MAX`, ...) are
    /// fixed on every model (C11 7.20.2.1); the others only on a declared
    /// one. `CHAR_MIN` and `CHAR_MAX` never are: whether plain `char` is
    /// signed is not part of a data model. A value outside `i64` is `None`.
    pub fn limit_macro(self, name: &str) -> Option<i64> {
        let exact = |bits: u32, signed: bool, max: bool| -> Option<i64> {
            let v: i128 = match (signed, max) {
                (true, true) => (1i128 << (bits - 1)) - 1,
                (true, false) => -(1i128 << (bits - 1)),
                (false, _) => (1i128 << bits) - 1,
            };
            i64::try_from(v).ok()
        };
        let exact_width = match name {
            "INT8_MAX" => Some((8, true, true)),
            "INT8_MIN" => Some((8, true, false)),
            "UINT8_MAX" => Some((8, false, true)),
            "INT16_MAX" => Some((16, true, true)),
            "INT16_MIN" => Some((16, true, false)),
            "UINT16_MAX" => Some((16, false, true)),
            "INT32_MAX" => Some((32, true, true)),
            "INT32_MIN" => Some((32, true, false)),
            "UINT32_MAX" => Some((32, false, true)),
            "INT64_MAX" => Some((64, true, true)),
            "INT64_MIN" => Some((64, true, false)),
            _ => None,
        };
        if let Some((bits, signed, max)) = exact_width {
            return exact(bits, signed, max);
        }
        let (signed, rank, max) = match name {
            "CHAR_BIT" => return self.exact_width(Rank::Char).map(i64::from),
            "SCHAR_MAX" => (true, Rank::Char, true),
            "SCHAR_MIN" => (true, Rank::Char, false),
            "UCHAR_MAX" => (false, Rank::Char, true),
            "SHRT_MAX" => (true, Rank::Short, true),
            "SHRT_MIN" => (true, Rank::Short, false),
            "USHRT_MAX" => (false, Rank::Short, true),
            "INT_MAX" => (true, Rank::Int, true),
            "INT_MIN" => (true, Rank::Int, false),
            "UINT_MAX" => (false, Rank::Int, true),
            "LONG_MAX" => (true, Rank::Long, true),
            "LONG_MIN" => (true, Rank::Long, false),
            "ULONG_MAX" => (false, Rank::Long, true),
            "LLONG_MAX" => (true, Rank::LongLong, true),
            "LLONG_MIN" => (true, Rank::LongLong, false),
            _ => return None,
        };
        let (lo, hi) = self.range(signed, rank)?;
        i64::try_from(if max { hi } else { lo }).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_knows_only_the_minimums_and_the_exact_width_types() {
        let iso = DataModel::Iso;
        assert_eq!(iso.exact_width(Rank::Int), None);
        assert_eq!(iso.min_width(Rank::Int), 16);
        assert_eq!(iso.min_width(Rank::Long), 32);
        assert_eq!(iso.guaranteed_range(true, Rank::Int), (-32767, 32767));
        assert_eq!(iso.guaranteed_range(false, Rank::Char), (0, 255));
        assert_eq!(iso.range(true, Rank::Int), None);
        assert_eq!(iso.limit_macro("INT_MAX"), None);
        assert_eq!(iso.limit_macro("CHAR_BIT"), None);
        assert_eq!(iso.limit_macro("INT32_MAX"), Some(2147483647));
        assert_eq!(iso.limit_macro("INT8_MIN"), Some(-128));
        assert_eq!(iso.sizeof_bytes(Rank::Char), Some(1));
        assert_eq!(iso.sizeof_bytes(Rank::Int), None);
        assert_eq!(iso.pointer_width(), None);
    }

    #[test]
    fn narrower_is_a_question_of_rank_and_width() {
        let iso = DataModel::Iso;
        let int = iso.width_of(Rank::Int);
        // short may be narrower than int, or as wide.
        assert!(iso.width_of(Rank::Short).may_be_narrower_than(int));
        assert!(!iso.width_of(Rank::Long).may_be_narrower_than(int));
        // int may be wider than 32 bits, so uint32_t may be the narrower.
        let (unsigned, u32w) = iso.spelled_width("uint32_t").unwrap();
        assert!(unsigned && u32w.may_be_narrower_than(int));
        let lp64 = DataModel::Lp64;
        let (_, u32w) = lp64.spelled_width("uint32_t").unwrap();
        assert_eq!(u32w.rank, Some(Rank::Int));
        assert!(!u32w.may_be_narrower_than(lp64.width_of(Rank::Int)));
        assert!(lp64
            .width_of(Rank::Short)
            .may_be_narrower_than(lp64.width_of(Rank::Int)));
        // On LLP64 long is not wider than int, and size_t is long long.
        let llp64 = DataModel::Llp64;
        assert_eq!(
            llp64.spelled_width("size_t").unwrap().1.rank,
            Some(Rank::LongLong)
        );
        assert_eq!(iso.spelled_width("size_t").unwrap().1.min, 16);
        let size_t = iso.spelled_width("size_t").unwrap().1;
        assert!(!size_t.may_be_narrower_than(size_t));
        // LLP64's 64-bit size_t is wider than its 32-bit unsigned long.
        assert!(iso.width_of(Rank::Long).may_be_narrower_than(size_t));
        assert_eq!(iso.spelled_width("widget_t"), None);
    }

    #[test]
    fn a_declared_model_fixes_every_width() {
        assert_eq!(DataModel::Lp64.exact_width(Rank::Long), Some(64));
        assert_eq!(DataModel::Llp64.exact_width(Rank::Long), Some(32));
        assert_eq!(DataModel::Ilp32.pointer_width(), Some(32));
        assert_eq!(DataModel::Lp64.limit_macro("INT_MAX"), Some(2147483647));
        assert_eq!(DataModel::Lp64.limit_macro("LONG_MAX"), Some(i64::MAX));
        assert_eq!(DataModel::Llp64.limit_macro("LONG_MAX"), Some(2147483647));
        assert_eq!(DataModel::Lp64.limit_macro("ULONG_MAX"), None);
        assert_eq!(DataModel::Lp64.limit_macro("CHAR_MAX"), None);
        assert_eq!(DataModel::Lp64.sizeof_bytes(Rank::Long), Some(8));
        assert_eq!(
            DataModel::Lp64.guaranteed_range(true, Rank::Int).0,
            -2147483648
        );
    }
}
