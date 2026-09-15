//! Preprocessor-dead line ranges under the ONE platform profile a scan
//! assumes, for collectors that must keep a single definition per name.
//!
//! aurora-lint has no preprocessor, so a per-file collector building a flat
//! `name -> fact` table (`ProjectContext::typedef_types`, `function_macros`,
//! `macro_constants`, ...) sees every conditional (re)definition of a name in
//! file order and has to pick one. "First wins" or "last wins" is a coin
//! flip against a platform split: hostap's `src/utils/common.h` defines
//! `u16` three times -- `#ifdef _MSC_VER` (`UINT16`), `#ifdef __vxworks`
//! (`UINT16`), `#ifndef WPA_TYPES_DEFINED` (`uint16_t`) -- and first-wins
//! kept the Windows one, a type nothing in a POSIX corpus ever defines, so
//! every width-sensitive rule saw `u16` as unresolvable (task 1142: EXP14-C
//! alone lost 59 of 62 labeled hostap TPs to this).
//!
//! `lang_parsing_substrate::dead_code_ranges` cannot settle that on its own:
//! it classifies a branch dead only on evidence the file itself contains, and
//! no portable file ever `#define`s `_MSC_VER`. The seeded variant used here,
//! [`lang_parsing_substrate::dead_code_ranges_with_assumptions`], takes the
//! caller's word for exactly that category of compiler-predefined platform
//! macro. A collector then skips any definition landing in a dead region and
//! keeps its existing tie-break for the rest -- a redefinition under a
//! build-config macro the profile has no opinion about (`#ifdef WPA_TRACE`,
//! `#if __BYTE_ORDER == ...`) stays Neutral and is picked exactly as before.
//!
//! **One profile per scan, POSIX by default.** The suite's real-world
//! oracles are single-platform per codebase, and a platform-visibility gap is
//! answered by onboarding a codebase for that platform (ventoy is the Win32
//! one), not by scanning one tree under several assumption tables. The
//! profile is a single choke point ([`platform_assumptions`]) so a future
//! `--platform`/`compile_commands.json`-derived table changes one function.
//! Struct-bodied collectors deliberately do NOT consult this: ventoy's
//! `process.h` wraps whole struct typedefs in `#if defined(_MSC_VER)`, and
//! dropping those under the POSIX default would trade a hostap fix for a
//! ventoy regression, while no corpus file has a same-file conditional
//! struct redefinition for the filter to arbitrate.
//!
//! Finding suppression (`suppression.rs`) still uses the UNSEEDED
//! `dead_code_ranges` on purpose: silencing every finding inside an
//! `#ifdef _WIN32` block corpus-wide is a separate policy decision from
//! which of several typedefs a name resolves to.

use lang_parsing_substrate::{
    dead_code_ranges_with_assumptions, posix_default_assumptions, PlatformAssumptions,
};
use tree_sitter::Node;

/// The platform profile every scan currently assumes. See the module doc
/// for why this is one table, not a per-codebase choice.
pub fn platform_assumptions() -> PlatformAssumptions {
    posix_default_assumptions()
}

/// 1-based inclusive line ranges of `source` that the assumed platform's
/// preprocessor would strip. Cheap to build (one line-oriented pass) and
/// meant to be built once per file per collector, not per node.
#[derive(Debug, Clone, Default)]
pub struct DeadRegions {
    ranges: Vec<(usize, usize)>,
}

impl DeadRegions {
    /// Dead regions of `source` under [`platform_assumptions`].
    pub fn of(source: &str) -> Self {
        let ranges = dead_code_ranges_with_assumptions(source, &platform_assumptions())
            .into_iter()
            .map(|r| (r.start_line, r.end_line))
            .collect();
        Self { ranges }
    }

    /// Whether 1-based `line` falls inside a dead region.
    pub fn contains_line(&self, line: usize) -> bool {
        self.ranges
            .iter()
            .any(|&(start, end)| line >= start && line <= end)
    }

    /// Whether `node` starts inside a dead region. A definition is one
    /// directive or one declaration, so its first line decides.
    pub fn contains_node(&self, node: &Node) -> bool {
        self.contains_line(node.start_position().row + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOSTAP_COMMON_H: &str = "\
#ifdef _MSC_VER
typedef UINT16 u16;
#define WPA_TYPES_DEFINED
#endif /* _MSC_VER */

#ifdef __vxworks
typedef UINT16 u16;
#define WPA_TYPES_DEFINED
#endif /* __vxworks */

#ifndef WPA_TYPES_DEFINED
typedef uint16_t u16;
#define WPA_TYPES_DEFINED
#endif /* !WPA_TYPES_DEFINED */
";

    #[test]
    fn posix_profile_kills_msc_and_vxworks_arms_but_not_the_fallback() {
        let dead = DeadRegions::of(HOSTAP_COMMON_H);
        assert!(dead.contains_line(2), "_MSC_VER arm is dead");
        assert!(dead.contains_line(7), "__vxworks arm is dead");
        // A `#define WPA_TYPES_DEFINED` inside a dead arm must not count as
        // evidence, or the real fallback arm would read as dead too.
        assert!(
            !dead.contains_line(12),
            "the #ifndef WPA_TYPES_DEFINED arm is the live one"
        );
    }

    #[test]
    fn build_config_macro_stays_neutral() {
        let dead = DeadRegions::of(
            "#ifdef WPA_TRACE\n#define os_strdup(s) trace_strdup(s)\n#else\n#define os_strdup(s) strdup(s)\n#endif\n",
        );
        assert!(
            dead.ranges.is_empty(),
            "no opinion on WPA_TRACE: {:?}",
            dead
        );
    }

    #[test]
    fn local_define_overrides_the_assumption() {
        // Local evidence wins over the seeded table (substrate contract).
        let dead =
            DeadRegions::of("#define _WIN32 1\n#ifdef _WIN32\nint a;\n#else\nint b;\n#endif\n");
        assert!(!dead.contains_line(3));
        assert!(dead.contains_line(5));
    }
}
