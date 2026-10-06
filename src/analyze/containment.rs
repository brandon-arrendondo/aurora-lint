//! Graceful failure: a crash or a runaway in one rule on one file costs that
//! rule's findings for that file, is always reported, and never ends the
//! scan or passes as clean (ADR-0017).
//!
//! A rule that panicked on one construct in one file used to take the whole
//! scan down with it: the panic crossed the rayon worker, `collect` re-raised
//! it on the main thread, and the process exited 101 with no findings at all.
//! A rule caught in a loop that never ends hung the scan the same way.
//!
//! [`contain`] runs one unit of work -- one rule's check of one file, one
//! file's parse and analysis, one file's prescan -- under `catch_unwind` and
//! under a [`checkpoint`] budget, and turns either way of not finishing into a
//! [`Failure`]. The caller records it as a [`ScanFailure`] and goes on.
//!
//! **Bounds are failures too.** Work that stops because it ran out of budget
//! has not shown there is nothing to report; treating it as "no finding"
//! would be unsound. So a budget hit is reported exactly like a crash: a
//! stderr line, a SARIF notification and exit [`EXIT_INCOMPLETE`].
//!
//! - The step budget is deterministic: [`checkpoint`] counts calls, so the
//!   same input on any machine stops at the same step.
//! - The time limit is the last resort for the one case a step count cannot
//!   see, a loop with no checkpoint in it: a checkpoint past the deadline
//!   unwinds the work, and the [watchdog](start_watchdog) ends the scan with
//!   exit 3 if a unit of work is still running long after its deadline.
//!
//! **Escalation** ([`Escalation`]): a rule that fails on
//! [`ABANDON_AFTER_FILES`] different files is abandoned for the scan; its
//! remaining files are skipped and all of its findings are withheld. Every
//! finding is withheld, not only those after the decision, so the output
//! does not depend on the order parallel workers met the failures.
//!
//! What a contained panic can leave behind. A rule gets a fresh instance per
//! file, so its own state dies with the file. Process-wide `Mutex`es in this
//! crate recover from poisoning (`lock().unwrap_or_else(|e| e.into_inner())`),
//! and a `OnceLock` whose initialiser panicked stays empty and is retried. The
//! one thread-local that carries rows across a rule's call is the
//! deallocator-candidate buffer, which the caller rolls back
//! ([`super::deallocator_candidates::pending_len`]). A per-file cache that a
//! failing rule had half-filled could still mislead a later rule on the SAME
//! file; that is why a failure names the file as well as the rule.

// Containment needs unwinding: under `panic = "abort"` `catch_unwind` catches
// nothing and a rule's panic ends the scan with no output again.
#[cfg(panic = "abort")]
compile_error!("aurora-lint contains rule panics and must be built with panic = \"unwind\"");

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap};
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Mutex, Once, OnceLock};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

/// The exit status of a scan that completed but is incomplete: some unit of
/// work crashed or ran out of budget. Distinct from `1` (findings over a
/// `--fail-on-*` threshold) and `2` (the scan could not run), and takes
/// precedence over `1`.
pub const EXIT_INCOMPLETE: i32 = 3;

/// How many different files a rule may fail on before the scan abandons it.
/// One failure is a construct the rule mishandles; three in one scan says the
/// rule cannot be trusted on this code base.
pub const ABANDON_AFTER_FILES: usize = 3;

/// The default step budget per unit of work: far above anything the
/// benchmark corpora reach (ADR-0017 records the measurement), so that only
/// a runaway hits it.
pub const DEFAULT_STEP_LIMIT: u64 = 50_000_000;

/// The default time limit per unit of work, in seconds.
pub const DEFAULT_TIME_LIMIT_SECS: u64 = 300;

/// Where in the scan a failure happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stage {
    /// Collecting one file's cross-file facts before any rule runs. The
    /// file's facts are missing, which can change findings in OTHER files
    /// in either direction.
    Prescan,
    /// Reading, parsing or analysing one file around its rules: the file
    /// contributes no findings.
    File,
    /// One rule's check of one file. Every other finding stands.
    Rule,
}

/// Why a unit of work did not finish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cause {
    /// It panicked: a bug.
    Panic,
    /// It reached its step budget: a runaway, or input far beyond anything
    /// measured.
    StepLimit,
    /// It ran past its time limit.
    TimeLimit,
    /// An analysis reached one of its own iteration caps, past which its
    /// results are not converged ([`cap_reached`]).
    Cap,
}

impl Cause {
    fn word(self) -> &'static str {
        match self {
            Cause::Panic => "crashed",
            Cause::StepLimit => "step limit",
            Cause::TimeLimit => "time limit",
            Cause::Cap => "analysis cap",
        }
    }
}

/// One unit of work that did not finish, as [`contain`] returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// Why.
    pub cause: Cause,
    /// The panic message, or what the bound was.
    pub message: String,
    /// Where in aurora-lint's own source it stopped (`file:line:col`).
    pub location: Option<String>,
}

/// One failure, placed: which stage, file and rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScanFailure {
    /// Whether one rule, the whole file, or the file's cross-file facts were
    /// lost.
    pub stage: Stage,
    /// The file being analysed.
    pub file: String,
    /// The rule, for [`Stage::Rule`].
    pub rule_id: Option<String>,
    /// Why the work stopped.
    pub cause: Cause,
    /// The panic message, or what the bound was.
    pub message: String,
    /// Where in aurora-lint's own source it stopped (`file:line:col`).
    pub location: Option<String>,
}

impl ScanFailure {
    /// Place a [`Failure`].
    pub fn new(stage: Stage, file: &str, rule_id: Option<&str>, failure: Failure) -> Self {
        Self {
            stage,
            file: file.to_string(),
            rule_id: rule_id.map(str::to_string),
            cause: failure.cause,
            message: failure.message,
            location: failure.location,
        }
    }

    /// One line, stable enough for a log scraper:
    /// `rule failure (CAUSE): RULE: FILE: MESSAGE [at LOCATION]`,
    /// `file failure (CAUSE): FILE: ...` or `prescan failure (CAUSE): FILE: ...`.
    pub fn render(&self) -> String {
        let at = self
            .location
            .as_deref()
            .map(|l| format!(" [at {l}]"))
            .unwrap_or_default();
        let cause = self.cause.word();
        match (self.stage, &self.rule_id) {
            (Stage::Rule, Some(rule)) => format!(
                "rule failure ({cause}): {rule}: {}: {}{at}",
                self.file, self.message
            ),
            (Stage::Prescan, _) => {
                format!(
                    "prescan failure ({cause}): {}: {}{at}",
                    self.file, self.message
                )
            }
            _ => format!(
                "file failure ({cause}): {}: {}{at}",
                self.file, self.message
            ),
        }
    }
}

// -- limits -----------------------------------------------------------------

/// The bounds every unit of work runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Checkpoints one unit of work may pass; `None` is unbounded.
    pub steps: Option<u64>,
    /// Wall-clock time one unit of work may take; `None` is unbounded.
    pub time: Option<Duration>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            steps: Some(DEFAULT_STEP_LIMIT),
            time: Some(Duration::from_secs(DEFAULT_TIME_LIMIT_SECS)),
        }
    }
}

static LIMITS: OnceLock<Mutex<Limits>> = OnceLock::new();

fn limits_cell() -> &'static Mutex<Limits> {
    LIMITS.get_or_init(|| Mutex::new(Limits::default()))
}

/// Set the bounds for this process's scans (`--rule-step-limit`,
/// `--rule-time-limit`).
pub fn set_limits(limits: Limits) {
    *limits_cell().lock().unwrap_or_else(|e| e.into_inner()) = limits;
}

/// The bounds in force.
pub fn limits() -> Limits {
    *limits_cell().lock().unwrap_or_else(|e| e.into_inner())
}

/// The payload a bound unwinds with, so [`contain`] can tell it from a bug.
#[derive(Debug)]
struct BoundHit(Cause, String);

/// One unit of work's budget, per thread.
#[derive(Clone, Copy)]
struct Budget {
    steps: u64,
    step_limit: Option<u64>,
    deadline: Option<Instant>,
}

thread_local! {
    /// Depth of [`contain`] calls active on this thread.
    static CONTAINING: Cell<usize> = const { Cell::new(0) };
    /// The message and location the hook saw for the panic being contained.
    static CAUGHT: RefCell<Option<(String, Option<String>)>> = const { RefCell::new(None) };
    /// The innermost unit of work's budget; `None` outside any.
    static BUDGET: Cell<Option<Budget>> = const { Cell::new(None) };
}

/// One step of possibly unbounded work: call it once per iteration of a
/// worklist, fixpoint or walk whose length the input decides. Free outside
/// [`contain`]; inside, a unit of work past its step budget or its deadline
/// stops here and is reported (ADR-0017).
#[inline]
pub fn checkpoint() {
    BUDGET.with(|b| {
        let Some(mut budget) = b.get() else {
            return;
        };
        budget.steps += 1;
        b.set(Some(budget));
        if budget.step_limit.is_some_and(|limit| budget.steps > limit) {
            panic::panic_any(BoundHit(
                Cause::StepLimit,
                format!(
                    "stopped after {} steps (--rule-step-limit)",
                    budget.step_limit.unwrap_or_default()
                ),
            ));
        }
        // The clock is read every 4096 steps, not on each one.
        if budget.steps % 4096 == 0 && budget.deadline.is_some_and(|d| Instant::now() > d) {
            panic::panic_any(BoundHit(
                Cause::TimeLimit,
                format!(
                    "stopped after {}s (--rule-time-limit)",
                    limits().time.unwrap_or_default().as_secs()
                ),
            ));
        }
    });
}

/// An analysis reached an iteration cap that only a runaway should reach
/// (`what` names it): its results past that point are not converged and may
/// be unsound, so inside [`contain`] the unit of work stops and is reported
/// like a crash (ADR-0017). Outside any unit of work -- a cross-file pass on
/// the main thread -- it warns on stderr once per cap and returns, and the
/// caller stops iterating as it always did.
pub fn cap_reached(what: &str) {
    if BUDGET.with(|b| b.get()).is_some() {
        panic::panic_any(BoundHit(
            Cause::Cap,
            format!("{what} reached its iteration cap without converging"),
        ));
    }
    static WARNED: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    let first = WARNED
        .get_or_init(|| Mutex::new(BTreeSet::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(what.to_string());
    if first {
        eprintln!(
            "Warning: {what} reached its iteration cap without converging; its results may be \
             incomplete"
        );
    }
}

/// An analysis reached an iteration cap that real code is known to reach,
/// because the analysis does not always converge: `what` names it. The
/// caller stops iterating as before and keeps what it has, so findings are
/// unchanged, but it is not silent: every occurrence is counted, and the
/// scan reports the counts as warnings on stderr and in SARIF
/// ([`take_not_converged`]). ADR-0017 records which analyses are on this
/// list and why; each one leaves it when its convergence is fixed.
pub fn not_converged(what: &'static str) {
    *NOT_CONVERGED
        .get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(what)
        .or_insert(0) += 1;
}

static NOT_CONVERGED: OnceLock<Mutex<std::collections::BTreeMap<&'static str, u64>>> =
    OnceLock::new();

/// Each [`not_converged`] analysis and how many times it stopped short in
/// this process, sorted; the counts reset.
pub fn take_not_converged() -> Vec<(String, u64)> {
    std::mem::take(
        &mut *NOT_CONVERGED
            .get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
            .lock()
            .unwrap_or_else(|e| e.into_inner()),
    )
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

/// The most steps any one unit of work has taken in this process, for
/// measuring how far the busiest real input is from the step budget
/// (`AURORA_LINT_STEP_STATS=1` prints it after a scan).
static MAX_STEPS_SEEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static MAX_STEPS_LABEL: OnceLock<Mutex<String>> = OnceLock::new();

/// The busiest unit of work so far: (steps, label).
pub fn max_steps_seen() -> (u64, String) {
    let label = MAX_STEPS_LABEL
        .get_or_init(|| Mutex::new(String::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    (
        MAX_STEPS_SEEN.load(std::sync::atomic::Ordering::Relaxed),
        label,
    )
}

fn note_steps(steps: u64, label: &str) {
    use std::sync::atomic::Ordering;
    if steps > MAX_STEPS_SEEN.load(Ordering::Relaxed)
        && MAX_STEPS_SEEN.fetch_max(steps, Ordering::Relaxed) < steps
    {
        *MAX_STEPS_LABEL
            .get_or_init(|| Mutex::new(String::new()))
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = label.to_string();
    }
}

// -- containment --------------------------------------------------------------

/// Install, once per process, a panic hook that stays quiet about a panic
/// [`contain`] is about to catch (the scan reports it as a [`ScanFailure`]
/// instead of the default "thread panicked" text) and defers to the previous
/// hook for every other panic.
fn install_hook() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if CONTAINING.with(|c| c.get()) == 0 {
                previous(info);
                return;
            }
            let location = info
                .location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
            CAUGHT.with(|c| *c.borrow_mut() = Some((payload_text(info.payload()), location)));
        }));
    });
}

fn payload_text(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(BoundHit(_, s)) = payload.downcast_ref::<BoundHit>() {
        s.clone()
    } else {
        "panic with a non-string payload".to_string()
    }
}

/// Run one unit of work, named `label` for the watchdog. A panic inside it,
/// or a [`checkpoint`] past its budget, becomes `Err(Failure)` instead of
/// unwinding further.
///
/// A nested call gets a budget of its own and gives the enclosing one back
/// when it returns, so a rule's steps are not charged to its file.
///
/// `AssertUnwindSafe` is deliberate: the closures this wraps borrow the
/// file's tree, source and shared context, none of which a check mutates
/// except through the interior-mutability cases the module doc lists.
pub fn contain<R>(label: &str, f: impl FnOnce() -> R) -> Result<R, Failure> {
    install_hook();
    let limits = limits();
    let started = Instant::now();
    let outer = BUDGET.with(|b| {
        b.replace(Some(Budget {
            steps: 0,
            step_limit: limits.steps,
            deadline: limits.time.map(|t| started + t),
        }))
    });
    CONTAINING.with(|c| c.set(c.get() + 1));
    let token = watchdog_enter(label, started);
    let result = panic::catch_unwind(AssertUnwindSafe(f));
    watchdog_leave(token);
    CONTAINING.with(|c| c.set(c.get() - 1));
    if let Some(spent) = BUDGET.with(|b| b.replace(outer)) {
        note_steps(spent.steps, label);
    }
    result.map_err(|payload| {
        let (message, location) = CAUGHT
            .with(|c| c.borrow_mut().take())
            .unwrap_or_else(|| (payload_text(payload.as_ref()), None));
        let cause = payload
            .downcast_ref::<BoundHit>()
            .map_or(Cause::Panic, |b| b.0);
        Failure {
            cause,
            message,
            location,
        }
    })
}

// -- watchdog -------------------------------------------------------------------

/// Units of work running now: thread -> (label, started), innermost last.
type Running = Mutex<HashMap<ThreadId, Vec<(String, Instant)>>>;
static RUNNING: OnceLock<Running> = OnceLock::new();

fn running() -> &'static Running {
    RUNNING.get_or_init(|| Mutex::new(HashMap::new()))
}

fn watchdog_enter(label: &str, started: Instant) -> bool {
    if !WATCHING.get().copied().unwrap_or(false) {
        return false;
    }
    running()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(std::thread::current().id())
        .or_default()
        .push((label.to_string(), started));
    true
}

fn watchdog_leave(token: bool) {
    if !token {
        return;
    }
    let mut map = running().lock().unwrap_or_else(|e| e.into_inner());
    let id = std::thread::current().id();
    if let Some(stack) = map.get_mut(&id) {
        stack.pop();
        if stack.is_empty() {
            map.remove(&id);
        }
    }
}

static WATCHING: OnceLock<bool> = OnceLock::new();

/// Start, once per process, the last-resort watchdog: a thread that ends the
/// scan with [`EXIT_INCOMPLETE`] when a unit of work is still running twice
/// its time limit (and at least a minute) after it started -- a loop with no
/// [`checkpoint`] in it, which no budget can stop from inside. It names the
/// unit on stderr first. A no-op when no time limit is set.
pub fn start_watchdog() {
    let Some(limit) = limits().time else {
        return;
    };
    if WATCHING.set(true).is_err() {
        return;
    }
    let grace = (limit * 2).max(limit + Duration::from_secs(60));
    std::thread::Builder::new()
        .name("aurora-lint-watchdog".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_secs(1));
            let now = Instant::now();
            let stuck = running()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .filter_map(|stack| stack.first())
                .find(|(_, started)| now.duration_since(*started) > grace)
                .map(|(label, started)| (label.clone(), now.duration_since(*started)));
            if let Some((label, ran)) = stuck {
                eprintln!(
                    "Error: hang: {label} has run {}s without reaching a checkpoint; \
                     ending the scan. Scan INCOMPLETE; no findings were written. \
                     This is an aurora-lint bug; please report it.",
                    ran.as_secs()
                );
                std::process::exit(EXIT_INCOMPLETE);
            }
        })
        .ok();
}

// -- escalation ------------------------------------------------------------------

/// Per-scan record of which rules failed on which files, shared by every
/// worker. See the module doc.
#[derive(Debug, Default)]
pub struct Escalation {
    failed: Mutex<HashMap<String, BTreeSet<String>>>,
}

impl Escalation {
    /// A fresh record.
    pub fn new() -> Self {
        Self::default()
    }

    /// Note that `rule` failed on `file`.
    pub fn record(&self, rule: &str, file: &str) {
        self.failed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(rule.to_string())
            .or_default()
            .insert(file.to_string());
    }

    /// Whether `rule` has failed on enough files to be abandoned.
    pub fn abandoned(&self, rule: &str) -> bool {
        self.failed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(rule)
            .is_some_and(|files| files.len() >= ABANDON_AFTER_FILES)
    }

    /// Every abandoned rule, sorted.
    pub fn abandoned_rules(&self) -> Vec<String> {
        let failed = self.failed.lock().unwrap_or_else(|e| e.into_inner());
        let out: BTreeSet<&String> = failed
            .iter()
            .filter(|(_, files)| files.len() >= ABANDON_AFTER_FILES)
            .map(|(rule, _)| rule)
            .collect();
        out.into_iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_passes_through() {
        assert_eq!(contain("t", || 7), Ok(7));
    }

    #[test]
    fn a_panic_becomes_its_message_and_location() {
        let f = contain("t", || -> () { panic!("boom {}", 1) }).unwrap_err();
        assert_eq!(f.cause, Cause::Panic);
        assert_eq!(f.message, "boom 1");
        assert!(f.location.unwrap().contains("containment.rs"));
    }

    #[test]
    fn a_slice_panic_is_contained() {
        let text = String::from("sizeof x) + (y");
        let (open, close) = (text.find('(').unwrap(), text.find(')').unwrap());
        let err = contain("t", || text[open + 1..close].len()).unwrap_err();
        assert!(err.message.contains("begin > end"), "{}", err.message);
    }

    #[test]
    fn nesting_keeps_the_hook_quiet_until_the_outermost_returns() {
        let outer = contain("outer", || {
            contain("inner", || -> () { panic!("inner") })
                .unwrap_err()
                .message
        });
        assert_eq!(outer.unwrap(), "inner");
    }

    #[test]
    fn a_checkpoint_outside_contain_is_free() {
        for _ in 0..10 {
            checkpoint();
        }
    }

    #[test]
    fn the_step_budget_stops_a_runaway_deterministically() {
        // A private budget: set via BUDGET directly so a parallel test that
        // reads the global limits is not affected.
        let run = || {
            contain("t", || {
                BUDGET.with(|b| {
                    b.set(Some(Budget {
                        steps: 0,
                        step_limit: Some(1000),
                        deadline: None,
                    }))
                });
                let mut n = 0u64;
                loop {
                    checkpoint();
                    n += 1;
                    if n > 1_000_000 {
                        return n;
                    }
                }
            })
        };
        let f = run().unwrap_err();
        assert_eq!(f.cause, Cause::StepLimit);
        assert!(f.message.contains("1000 steps"), "{}", f.message);
        assert_eq!(run().unwrap_err(), f, "same input, same stop");
    }

    #[test]
    fn a_nested_unit_gives_the_outer_budget_back() {
        let steps_after = contain("outer", || {
            checkpoint();
            let _ = contain("inner", || {
                for _ in 0..100 {
                    checkpoint();
                }
            });
            BUDGET.with(|b| b.get().unwrap().steps)
        })
        .unwrap();
        assert_eq!(steps_after, 1);
    }

    #[test]
    fn escalation_abandons_after_three_files_whatever_the_order() {
        let e = Escalation::new();
        e.record("X", "c.c");
        e.record("X", "a.c");
        e.record("X", "a.c");
        assert!(!e.abandoned("X"), "one file twice is still one file");
        e.record("X", "b.c");
        assert!(e.abandoned("X"));
        assert!(!e.abandoned("Y"));
        assert_eq!(e.abandoned_rules(), vec!["X".to_string()]);
    }

    #[test]
    fn render_names_stage_cause_rule_and_file() {
        let f = ScanFailure {
            stage: Stage::Rule,
            file: "a.c".into(),
            rule_id: Some("MEM35-C".into()),
            cause: Cause::Panic,
            message: "begin > end".into(),
            location: Some("mem35_c.rs:180:50".into()),
        };
        assert_eq!(
            f.render(),
            "rule failure (crashed): MEM35-C: a.c: begin > end [at mem35_c.rs:180:50]"
        );
        let p = ScanFailure {
            stage: Stage::Prescan,
            rule_id: None,
            cause: Cause::StepLimit,
            ..f
        };
        assert!(p.render().starts_with("prescan failure (step limit): a.c:"));
    }
}
