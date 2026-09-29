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
