// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! Callees worth declaring as deallocators: `--report-deallocator-candidates`.
//!
//! A free counts only where the analyzer can show it: `free`, a function
//! whose body frees the argument, a macro whose expansion does, or a
//! deallocator the project declares (`[environment.deallocators]`,
//! `--deallocator`). A library's own `*_free`/`*_destroy`/`*_cleanup` has no
//! body in the scan, so an allocation handed to one is not released as far
//! as the rules can tell, and MEM31-C reports it leaked.
//!
//! This report lists those callees, so a user can declare the ones that
//! really are deallocators. A callee is listed when a call to it received
//! an allocation MEM31-C then reported leaked, it is shaped like a
//! deallocator by name (`ast_utils::is_deallocation_call_name`), and nothing
//! proves it frees anything. The name is read here and nowhere else: this
//! report is a diagnostic, never an input to a finding, and requesting it
//! changes no finding, no settings hash and no run id.
//!
//! Rows are collected per thread while a file's rules run
//! ([`record`]) and tagged with the file's path once they finish
//! ([`flush_file`]), so the rules themselves never need to know which file
//! they are looking at.

use serde::Serialize;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

static ENABLED: AtomicBool = AtomicBool::new(false);
static ROWS: Mutex<Vec<Sighting>> = Mutex::new(Vec::new());

thread_local! {
    static PENDING: RefCell<Vec<(String, usize, usize)>> = const { RefCell::new(Vec::new()) };
    /// Set while a pass whose rows must not count runs on this thread.
    static HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run `f` with nothing it records reaching the report: a second analysis
/// pass over a file already analysed (a member file's excluded arms, read
/// without generated headers) would count its candidates twice.
pub fn discarding<R>(f: impl FnOnce() -> R) -> R {
    let rollback = pending_len();
    HELD.with(|h| h.set(true));
    let out = f();
    HELD.with(|h| h.set(false));
    truncate_pending(rollback);
    out
}

/// One call to a candidate: the callee, the 1-based position of the
/// argument that received the leaked allocation, and where the call is.
#[derive(Debug, Clone)]
struct Sighting {
    callee: String,
    argument: usize,
    file: String,
    line: usize,
}

/// Turn collection on for this process. Off by default, so a scan that did
/// not ask for the report does no bookkeeping at all.
pub fn enable() {
    ENABLED.store(true, Ordering::Relaxed);
}

/// Whether the report was requested.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Record a call to `callee` on 1-based `line` of the file being analysed on
/// this thread, whose argument at 1-based position `argument` received an
/// allocation that was then reported leaked. A no-op unless [`enabled`].
pub fn record(callee: &str, argument: usize, line: usize) {
    if !enabled() {
        return;
    }
    PENDING.with(|p| p.borrow_mut().push((callee.to_string(), argument, line)));
}

/// How many rows this thread has recorded since the last flush: a rollback
/// point for [`truncate_pending`].
pub fn pending_len() -> usize {
    PENDING.with(|p| p.borrow().len())
}

/// Drop what this thread recorded after the rollback point `len`. A rule
/// that panicked part-way through a file (`containment`) leaves rows from a
/// check that never finished; they are not evidence of anything.
pub fn truncate_pending(len: usize) {
    PENDING.with(|p| p.borrow_mut().truncate(len));
}

/// Attach `file` to everything recorded on this thread since the last flush.
pub fn flush_file(file: &str) {
    if !enabled() || HELD.with(|h| h.get()) {
        return;
    }
    let pending = PENDING.with(|p| std::mem::take(&mut *p.borrow_mut()));
    if pending.is_empty() {
        return;
    }
    let mut rows = ROWS.lock().unwrap_or_else(|e| e.into_inner());
    rows.extend(
        pending
            .into_iter()
            .map(|(callee, argument, line)| Sighting {
                callee,
                argument,
                file: file.to_string(),
                line,
            }),
    );
}

/// One callee and argument position, over every call that sighted it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Candidate {
    /// The callee, as the rules resolve it through `#define` aliases.
    pub callee: String,
    /// 1-based, as `[environment.deallocators]` takes it.
    pub argument: usize,
    /// Calls to it that received an allocation MEM31-C reported leaked.
    pub count: usize,
    /// The file of the first such call, by file and line.
    pub sample_file: String,
    /// The 1-based line of that call.
    pub sample_line: usize,
}

/// Everything collected, grouped by callee and argument position.
#[derive(Debug, Clone, Serialize, Default)]
pub struct CandidateReport {
    /// Most-sighted first.
    pub candidates: Vec<Candidate>,
}

/// Drop every row collected so far: the rule that recorded them was
/// abandoned for the scan (`containment`), so they are withheld with its
/// findings.
pub fn discard_all() {
    ROWS.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// Group the rows collected so far into a report and clear them. Most
/// sightings first, then by name, so the output is deterministic.
pub fn take_report() -> CandidateReport {
    let rows = std::mem::take(&mut *ROWS.lock().unwrap_or_else(|e| e.into_inner()));
    CandidateReport::from_sightings(rows)
}

impl CandidateReport {
    fn from_sightings(rows: Vec<Sighting>) -> Self {
        let mut grouped: BTreeMap<(String, usize), Candidate> = BTreeMap::new();
        for row in rows {
            let entry = grouped
                .entry((row.callee.clone(), row.argument))
                .or_insert_with(|| Candidate {
                    callee: row.callee.clone(),
                    argument: row.argument,
                    count: 0,
                    sample_file: row.file.clone(),
                    sample_line: row.line,
                });
            entry.count += 1;
            if (row.file.as_str(), row.line) < (entry.sample_file.as_str(), entry.sample_line) {
                entry.sample_file = row.file;
                entry.sample_line = row.line;
            }
        }
        let mut candidates: Vec<Candidate> = grouped.into_values().collect();
        candidates.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.callee.cmp(&b.callee))
                .then_with(|| a.argument.cmp(&b.argument))
        });
        CandidateReport { candidates }
    }

    /// The human-readable section: the ask, the manifest key, then at most
    /// `max_rows` rows.
    pub fn render_text(&self, max_rows: usize) -> String {
        let mut out = String::from("Deallocator candidates\n");
        if self.candidates.is_empty() {
            out.push_str(
                "  None: no allocation MEM31-C reported leaked was handed to an unproven \
                 callee shaped like a deallocator.\n",
            );
            return out;
        }
        out.push_str(
            "  An allocation handed to one of these callees was reported leaked, because \
             nothing in the scan shows the callee freeing it. If a callee is a deallocator, \
             declare it in the manifest under [environment.deallocators] as \
             NAME = ARGUMENT (or pass --deallocator NAME=ARGUMENT).\n",
        );
        for c in self.candidates.iter().take(max_rows) {
            out.push_str(&format!(
                "  {} = {}  ({} call{}, e.g. {}:{})\n",
                c.callee,
                c.argument,
                c.count,
                if c.count == 1 { "" } else { "s" },
                c.sample_file,
                c.sample_line
            ));
        }
        if self.candidates.len() > max_rows {
            out.push_str(&format!(
                "  ... and {} more\n",
                self.candidates.len() - max_rows
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sighting(callee: &str, argument: usize, file: &str, line: usize) -> Sighting {
        Sighting {
            callee: callee.to_string(),
            argument,
            file: file.to_string(),
            line,
        }
    }

    #[test]
    fn sightings_group_by_callee_and_argument_with_the_earliest_sample() {
        let report = CandidateReport::from_sightings(vec![
            sighting("SSL_free", 1, "b.c", 9),
            sighting("SSL_free", 1, "a.c", 40),
            sighting("x_release", 2, "a.c", 3),
            sighting("SSL_free", 1, "a.c", 12),
        ]);
        assert_eq!(
            report.candidates,
            vec![
                Candidate {
                    callee: "SSL_free".into(),
                    argument: 1,
                    count: 3,
                    sample_file: "a.c".into(),
                    sample_line: 12,
                },
                Candidate {
                    callee: "x_release".into(),
                    argument: 2,
                    count: 1,
                    sample_file: "a.c".into(),
                    sample_line: 3,
                },
            ]
        );
        let text = report.render_text(1);
        assert!(text.contains("[environment.deallocators]"));
        assert!(text.contains("SSL_free = 1  (3 calls, e.g. a.c:12)"));
        assert!(text.contains("... and 1 more"));
    }
}
