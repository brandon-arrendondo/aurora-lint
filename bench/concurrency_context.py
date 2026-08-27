"""Concurrency-context-evidence classifier for CON03/07/33(+34/37)-C findings.

Follow-on from task 151 (docs/design/concurrency-rule-evaluation.md §4 item
B). Those three rules only check for *nearby syntactic protection* (a
volatile/atomic qualifier, a mutex, membership in a fixed unsafe-function
list) -- none of them ask whether the flagged code is ever reachable from a
second thread, a registered signal handler, or an ISR. Full reachability
analysis is task 608 (deliberately out of scope here); this module is the
cheap proxy the design doc calls for first: does the finding's *enclosing
translation unit* contain any textual evidence that a concurrent execution
path exists at all?

This is a per-TU heuristic, not a call-graph or reachability check -- a
`has_evidence: True` result means "this file has *something* that could
plausibly explain a race," not "this specific line is reachable from it."
That's why real-world adjudication (task 546/547/549) found single-threaded
codebases (mosquitto's broker event loop, cf. the design doc's root-cause
writeup) still carrying the bulk of the FP mass: those TUs show zero
evidence under any of the three patterns below.
"""

import re
from pathlib import Path

_THREAD_SPAWN_RE = re.compile(r"\b(?:pthread_create|thrd_create|CreateThread)\s*\(")
_SIGNAL_REGISTRATION_RE = re.compile(r"\b(?:signal|sigaction)\s*\(")

# The Catapult firmware audit (concurrency-rule-evaluation.md §1) found ~76-80%
# of that codebase's CON03/07-C findings traced to files containing a function
# named IRQ/interrupt/ISR -- a name-matching proxy, not a real ISR-registration
# check (the audit's own point was that name-matching alone isn't reliable,
# e.g. a poller named `DEV_APPROX_IRQProcess`). No such heuristic exists
# anywhere else in this codebase (checked src/rules/cert_c/CONC and
# docs/design/internal-capability-catalog.md) -- it's implemented fresh here,
# matching the pattern the audit described, not reused from existing code.
_ISR_NAME_DEF_RE = re.compile(
    r"\b\w*(?:isr|irq|interrupt)\w*\s*\([^;{}]*\)\s*\{", re.IGNORECASE
)
_ISR_MACRO_RE = re.compile(
    r"\bISR\s*\(|__attribute__\s*\(\s*\(\s*interrupt\b|\b__interrupt\b"
)


def classify_concurrency_context(source_path: Path) -> dict:
    """Scan one translation unit for evidence of a concurrent execution path.

    Returns booleans per evidence category plus `has_evidence` (their OR).
    An unreadable file returns all-False with `error` set instead of raising,
    so a caller batching many findings can skip/report rather than abort.
    """
    try:
        text = Path(source_path).read_text(errors="replace")
    except OSError as e:
        return {
            "thread_spawn": False,
            "signal_registration": False,
            "isr_like": False,
            "has_evidence": False,
            "error": str(e),
        }

    thread_spawn = bool(_THREAD_SPAWN_RE.search(text))
    signal_registration = bool(_SIGNAL_REGISTRATION_RE.search(text))
    isr_like = bool(_ISR_NAME_DEF_RE.search(text) or _ISR_MACRO_RE.search(text))
    return {
        "thread_spawn": thread_spawn,
        "signal_registration": signal_registration,
        "isr_like": isr_like,
        "has_evidence": thread_spawn or signal_registration or isr_like,
        "error": None,
    }


CONCURRENCY_RULES = ("CON03-C", "CON07-C", "CON33-C", "CON34-C", "CON37-C")


def concurrency_context_precision_split(
    db,
    bench_root: Path,
    project: str | None = None,
    rules=CONCURRENCY_RULES,
) -> dict:
    """Retroactively re-score labeled CON03/07/33(+34/37)-C ground truth,
    split by whether the flagged TU shows concurrency-context evidence.

    Answers design-doc §3 Q3: precision reported split by concurrency-context
    presence, not as one blended number. `db` is a BenchDB; `bench_root` is
    where each project's pinned checkout lives (BENCH_ROOT/<project>/...,
    matching ground_truth.file_path which is already project-relative).
    """
    labels = [
        row
        for row in db.get_ground_truth_labels(project=project)
        if row["rule_id"] in rules
    ]

    buckets = {
        "context_present": {"tp": 0, "fp": 0, "uncertain": 0},
        "context_absent": {"tp": 0, "fp": 0, "uncertain": 0},
    }
    verdict_key = {"TP": "tp", "FP": "fp", "uncertain": "uncertain"}
    findings = []
    missing_files = []

    for row in labels:
        src = Path(bench_root) / row["project"] / row["file_path"]
        evidence = classify_concurrency_context(src)
        if evidence["error"]:
            missing_files.append(str(src))
            continue
        bucket = "context_present" if evidence["has_evidence"] else "context_absent"
        key = verdict_key.get(row["verdict"])
        if key:
            buckets[bucket][key] += 1
        findings.append({**row, **evidence, "bucket": bucket})

    def with_precision(b):
        n = b["tp"] + b["fp"]
        return {**b, "precision_pct": (b["tp"] / n * 100) if n else None}

    return {
        "rules": list(rules),
        "project": project,
        "labeled_total": len(labels),
        "missing_files": missing_files,
        "buckets": {k: with_precision(v) for k, v in buckets.items()},
        "findings": findings,
    }
