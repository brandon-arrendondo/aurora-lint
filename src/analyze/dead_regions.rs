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
//! every width-sensitive rule saw `u16` as unresolvable (an earlier fix: EXP14-C
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
//! profile is a single choke point ([`platform_assumptions`]).
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
//!
//! # Declaring the profile instead of assuming it
//!
//! POSIX-by-default is a guess about the *platform*, and a guess is all it can
//! be with no build system in sight. But the axis that actually decides which
//! definition of a name wins is usually not the platform: measured over the
//! twelve pinned corpora, of 660 names with several live conditional
//! definitions, a compiler-predefined platform macro separates the arms for
//! ~176 of them and the project's own build configuration (`NDEBUG`,
//! `SQLITE_OMIT_*`, `CONFIG_*`, `HAVE_*`) for ~451
//! (`docs/design/multi-configuration-scanning.md` §6). sqlite's `ALWAYS(X)` is
//! the shape: three definitions over `SQLITE_OMIT_AUXILIARY_SAFETY_CHECKS` and
//! `NDEBUG`, none of them a platform, and first-wins keeps the
//! omit-safety-checks constant `(1)`.
//!
//! When the caller can say what the build actually defines, guessing is
//! unnecessary. [`declare_scan_profile`] installs that declaration once per
//! process, overlaid on the POSIX base so unlisted names keep their default;
//! `--compile-commands` supplies it from the database's own `-D`/`-U` state
//! ([`super::compile_commands::CompileDb::declared_macro_state`]). Absent that
//! flag nothing is declared and the table is exactly the POSIX default it has
//! always been, so the no-build-system path is unchanged.
//!
//! This is **name resolution only** (ADR-0010 Decision 3): a declared profile
//! changes which conditional definition of a name a collector keeps, and never
//! whether a finding is emitted. It is emphatically not a
//! `--assume-defined`-style suppression switch, which ADR-0010's Consequences
//! call a proposal to revisit the ADR rather than a feature.

use lang_parsing_substrate::{
    dead_code_ranges, dead_code_ranges_with_assumptions, posix_default_assumptions, DeadCodeReason,
    PlatformAssumptions,
};
use std::sync::OnceLock;
use tree_sitter::Node;

/// The profile in force for this process, once a caller has declared one.
/// Unset means "nobody declared anything", which reads as the POSIX default.
static SCAN_PROFILE: OnceLock<PlatformAssumptions> = OnceLock::new();

/// The macro state every collector in this scan assumes: the POSIX default,
/// or whatever [`declare_scan_profile`] installed over it. See the module doc
/// for why this is one table per scan, not a per-file or per-rule choice.
pub fn platform_assumptions() -> &'static PlatformAssumptions {
    SCAN_PROFILE.get_or_init(posix_default_assumptions)
}

/// Declare the build configuration this scan is analysing, as `name ->
/// defined`, overlaid on the POSIX default so a name the declaration does not
/// mention keeps its default treatment.
///
/// Call once, **before any collector runs** — the profile decides which
/// conditional definitions prescan keeps, so a declaration made afterwards
/// would apply to some tables and not others. `load_project_context` is the
/// one caller and does it ahead of prescan.
///
/// A declaration is *not* stronger than the file it is applied to: the
/// substrate lets a local `#define`/`#undef` override a seeded assumption from
/// the point it takes effect, which is the same direction as the compile
/// database's own "gap-filling, never overriding" rule for macro tables — real
/// source wins over a build flag either way.
///
/// # Errors
///
/// If a *different* profile is already in force. One process scans one
/// configuration (see the module doc); two declarations that disagree mean the
/// caller has mixed two scans, and silently honouring the first would leave
/// half the tables built under the other. Re-declaring the identical table is
/// fine.
pub fn declare_scan_profile(declared: PlatformAssumptions) -> Result<(), String> {
    let mut table = posix_default_assumptions();
    // The declaration wins over the default: a build that says `-U__linux__`
    // or `-D_WIN32` knows better than our guess.
    table.extend(declared);
    match SCAN_PROFILE.set(table) {
        Ok(()) => Ok(()),
        Err(rejected) => {
            if SCAN_PROFILE.get() == Some(&rejected) {
                Ok(())
            } else {
                Err(
                    "a different scan profile is already in force for this process; \
                     one process analyses one build configuration"
                        .to_string(),
                )
            }
        }
    }
}

/// What made a region dead: the file's own text, or the configuration the
/// scan assumed.
///
/// The substrate's [`DeadCodeReason`] cannot answer this by itself.
/// `AlwaysDefined`/`NeverDefined` are each produced by *two* causes — a local
/// `#define`/`#undef`, or a caller assumption about a macro the file never
/// mentions — and only the second is the profile's doing. Distinguishing them
/// is the whole point of ADR-0010 Decision 2 ("dead means provable from the
/// file itself"), so the distinction is measured rather than inferred from the
/// reason: a region that is dead with the assumption table *removed* is dead
/// on the file's own evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadEvidence {
    /// The file itself proves the arm dead — `#if 0`, a `__cplusplus` arm in a
    /// C translation unit, or a macro this file unconditionally `#define`s or
    /// `#undef`s. True under every configuration; no assumption involved.
    FileProven,
    /// The arm is dead only because the scan assumed a configuration:
    /// `#ifdef _WIN32` under the POSIX default, or an arm a
    /// `--compile-commands` declaration rules out. Right for the configuration
    /// assumed; says nothing about any other.
    AssumedConfiguration,
}

/// One dead range, with why it is dead and what decided it.
#[derive(Debug, Clone, Copy)]
struct DeadRegion {
    start: usize,
    end: usize,
    reason: DeadCodeReason,
    /// `None` until [`DeadRegions::attributed`] has measured it — the hot
    /// path does not pay for the second pass.
    evidence: Option<DeadEvidence>,
}

/// 1-based inclusive line ranges of `source` that the assumed platform's
/// preprocessor would strip. Cheap to build (one line-oriented pass) and
/// meant to be built once per file per collector, not per node.
#[derive(Debug, Clone, Default)]
pub struct DeadRegions {
    regions: Vec<DeadRegion>,
}

impl DeadRegions {
    /// Dead regions of `source` under [`platform_assumptions`].
    pub fn of(source: &str) -> Self {
        Self::under(source, platform_assumptions())
    }

    /// Dead regions of `source` under an explicitly supplied table, bypassing
    /// the process-wide profile. Exists so a caller (and a test) can ask about
    /// a configuration other than the one in force.
    pub fn under(source: &str, assumptions: &PlatformAssumptions) -> Self {
        let regions = dead_code_ranges_with_assumptions(source, assumptions)
            .into_iter()
            .map(|r| DeadRegion {
                start: r.start_line,
                end: r.end_line,
                reason: r.reason,
                evidence: None,
            })
            .collect();
        Self { regions }
    }

    /// Like [`DeadRegions::of`], and additionally attributes each region to
    /// the file or to the assumed configuration ([`DeadEvidence`]).
    ///
    /// Costs a second line-oriented pass, so it is opt-in: only reporting
    /// wants the attribution, and the collectors that run over every prescanned
    /// file do not. Nothing about which regions are dead changes.
    pub fn attributed(source: &str) -> Self {
        Self::attributed_under(source, platform_assumptions())
    }

    /// [`DeadRegions::attributed`] against an explicitly supplied table.
    pub fn attributed_under(source: &str, assumptions: &PlatformAssumptions) -> Self {
        let mut regions = Self::under(source, assumptions).regions;
        // The same file with no assumptions seeded: whatever is still dead is
        // dead on the file's own evidence. `#if 0` and `__cplusplus` need no
        // check — no assumption table can produce either.
        let file_proven: Vec<(usize, usize)> = dead_code_ranges(source)
            .into_iter()
            .map(|r| (r.start_line, r.end_line))
            .collect();
        for region in &mut regions {
            let proven = matches!(
                region.reason,
                DeadCodeReason::IfZero | DeadCodeReason::CppOnly
            ) || file_proven
                .iter()
                .any(|&(start, end)| region.start >= start && region.start <= end);
            region.evidence = Some(if proven {
                DeadEvidence::FileProven
            } else {
                DeadEvidence::AssumedConfiguration
            });
        }
        Self { regions }
    }

    /// Why 1-based `line` is dead, and what decided it — `None` if the line is
    /// live, or if this table was not built by [`DeadRegions::attributed`].
    pub fn evidence_for_line(&self, line: usize) -> Option<(DeadCodeReason, DeadEvidence)> {
        self.regions
            .iter()
            .find(|r| line >= r.start && line <= r.end)
            .and_then(|r| r.evidence.map(|e| (r.reason, e)))
    }

    /// Whether 1-based `line` falls inside a dead region.
    pub fn contains_line(&self, line: usize) -> bool {
        self.regions
            .iter()
            .any(|r| line >= r.start && line <= r.end)
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
    fn attribution_separates_the_profile_from_the_file() {
        // Three dead arms, one per cause: the profile's (_MSC_VER), the
        // file's own unconditional #define, and #if 0.
        let src = "\
#ifdef _MSC_VER
typedef UINT16 u16;
#endif
#define HAVE_IT
#ifndef HAVE_IT
int local_dead;
#endif
#if 0
int never;
#endif
";
        let dead = DeadRegions::attributed(src);
        assert_eq!(
            dead.evidence_for_line(2).map(|(_, e)| e),
            Some(DeadEvidence::AssumedConfiguration),
            "no file defines _MSC_VER; only the POSIX profile kills this arm"
        );
        assert_eq!(
            dead.evidence_for_line(6).map(|(_, e)| e),
            Some(DeadEvidence::FileProven),
            "the unconditional #define above the test is local proof"
        );
        assert_eq!(
            dead.evidence_for_line(9),
            Some((DeadCodeReason::IfZero, DeadEvidence::FileProven))
        );
        assert_eq!(dead.evidence_for_line(4), None, "live line has no evidence");
    }

    #[test]
    fn of_does_not_pay_for_attribution() {
        // `of` is the collector path: same ranges, evidence deliberately unset
        // rather than guessed, so a caller cannot read an attribution that was
        // never measured.
        let src = "#ifdef _MSC_VER
typedef UINT16 u16;
#endif
";
        let plain = DeadRegions::of(src);
        assert!(plain.contains_line(2));
        assert_eq!(plain.evidence_for_line(2), None);
        assert!(DeadRegions::attributed(src).evidence_for_line(2).is_some());
    }

    #[test]
    fn build_config_macro_stays_neutral() {
        let dead = DeadRegions::of(
            "#ifdef WPA_TRACE\n#define os_strdup(s) trace_strdup(s)\n#else\n#define os_strdup(s) strdup(s)\n#endif\n",
        );
        assert!(
            dead.regions.is_empty(),
            "no opinion on WPA_TRACE: {:?}",
            dead
        );
    }

    /// The declared-configuration cases go through `under`, not the global
    /// profile: `OnceLock` is per-process and the test binary runs them all in
    /// one, so a test that installed a profile would decide what every other
    /// test sees. `declare_scan_profile` itself is only the overlay + set, and
    /// the overlay is what these pin down.
    fn declared(pairs: &[(&str, bool)]) -> PlatformAssumptions {
        let mut table = posix_default_assumptions();
        table.extend(pairs.iter().map(|(n, v)| (n.to_string(), *v)));
        table
    }

    #[test]
    fn a_declared_define_kills_an_arm_a_default_scan_cannot_judge() {
        // A build-config axis: no platform macro appears, so the POSIX default
        // has no opinion and both arms stay live for first-wins to arbitrate.
        // The build saying -DWITH_TLS is what settles it.
        const SRC: &str = "\
#ifdef WITH_TLS
#define net_read(s) tls_read(s)
#else
#define net_read(s) read(s)
#endif
";
        let default = DeadRegions::of(SRC);
        assert!(
            !default.contains_line(2) && !default.contains_line(4),
            "no declaration: both arms live, first wins (unchanged behaviour)"
        );

        let declared_on = DeadRegions::under(SRC, &declared(&[("WITH_TLS", true)]));
        assert!(!declared_on.contains_line(2), "the declared arm is live");
        assert!(declared_on.contains_line(4), "its #else is dead");
    }

    /// The mechanism's ceiling, pinned deliberately: the substrate's scanner
    /// classifies `#if`/`#ifdef`/`#ifndef` and the matching `#else`, but an
    /// `#elif` condition is never evaluated -- it only closes a region the
    /// opening `#if` started. So sqlite's `ALWAYS(X)`, whose second definition
    /// sits in an `#elif !defined(NDEBUG)` arm, is NOT resolved by declaring
    /// `-DNDEBUG`, and no amount of declaration will do it until the substrate
    /// learns `#elif`. If this test starts failing because the arm became dead,
    /// that is the substrate gaining the capability -- widen the declaration's
    /// reach here and in `docs/design/multi-configuration-scanning.md` §7.
    #[test]
    fn an_elif_arm_is_beyond_what_a_declaration_can_settle() {
        const SRC: &str = "\
#if defined(SQLITE_OMIT_AUXILIARY_SAFETY_CHECKS)
# define ALWAYS(X) (1)
#elif !defined(NDEBUG)
# define ALWAYS(X) ((X)?1:(assert(0),0))
#else
# define ALWAYS(X) (X)
#endif
";
        let table = declared(&[
            ("NDEBUG", true),
            ("SQLITE_OMIT_AUXILIARY_SAFETY_CHECKS", false),
        ]);
        let dead = DeadRegions::under(SRC, &table);
        assert!(
            dead.contains_line(2),
            "the opening #if IS settled by the declaration"
        );
        assert!(
            !dead.contains_line(4),
            "but the #elif arm is not evaluated, so -DNDEBUG does not kill it"
        );
    }

    #[test]
    fn a_declared_undefine_kills_the_then_arm() {
        // -UCONFIG_SAE is a positive fact: the #ifdef arm cannot compile.
        let dead = DeadRegions::under(
            "#ifdef CONFIG_SAE\nint sae;\n#else\nint stub;\n#endif\n",
            &declared(&[("CONFIG_SAE", false)]),
        );
        assert!(dead.contains_line(2), "the -U'd arm is dead");
        assert!(!dead.contains_line(4), "its #else is the live one");
    }

    #[test]
    fn the_declaration_overrides_the_posix_default() {
        // A Windows build's database is the better authority on _WIN32 than our
        // POSIX guess, which would call this arm dead.
        let dead = DeadRegions::under(
            "#ifdef _WIN32\nint win;\n#else\nint posix;\n#endif\n",
            &declared(&[("_WIN32", true)]),
        );
        assert!(!dead.contains_line(2), "declared _WIN32 arm is live");
        assert!(dead.contains_line(4), "and the POSIX arm is the dead one");
    }

    #[test]
    fn a_name_the_declaration_does_not_mention_keeps_its_default() {
        let table = declared(&[("CONFIG_SAE", true)]);
        let dead = DeadRegions::under(
            "#ifdef _MSC_VER\nint msc;\n#endif\n#ifdef WPA_TRACE\nint trace;\n#endif\n",
            &table,
        );
        assert!(dead.contains_line(2), "_MSC_VER still undefined by default");
        assert!(
            !dead.contains_line(5),
            "WPA_TRACE is unmentioned either way, so it stays Neutral"
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
