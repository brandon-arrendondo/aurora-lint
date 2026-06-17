# DB_UPDATE — Task DB changes from Catapult FP review

> Generated 2026-06-17 by work-machine Claude session.
> Source: `/home/brandon/data/e_catapult_longood/code_review/FPs.md`
> Do NOT add the MEM30-C storage-class task (Task 1) — it is being fixed in this same
> session and will be committed before this file is ingested.

---

## NEW TASK — Add to DB

### `#if 0` preprocessor exclusion

```
title:  Exclude `#if 0` dead-code blocks from analysis
details:
  sqc flagged dev_stu.c:505 (MEM30-C) for code inside a `#if 0 … #endif` block that
  is never compiled. Scanning dead preprocessor branches produces unfixable noise and
  inflates counts, masking real issues.

  Fix scope: preprocessor/prescan stage — detect and mark `#if 0` regions; skip them
  in all rule checkers.

  Evidence: FP-002 in Catapult RC624 V1.5.8 firmware review (1 hit, but cross-cutting
  correctness concern for any codebase that uses `#if 0` to comment out code).
tag:    analysis, preprocessor
priority: 2
```

---

## UPDATE EXISTING TASK — Task 151 (CON33-C/CON07-C triage)

Task 151 currently covers CON07-C and CON33-C. The Catapult firmware audit adds
significant new data and introduces CON03-C as a separate, large FP source.

```
Append to details of task 151:

--- 2026-06-17 Catapult audit update ---

New CON03-C data (not previously in task 151):
sqc's CON03-C heuristic flags ALL file-scope statics in any translation unit that
contains a function named *IRQ*, *interrupt*, or *ISR*, without checking whether the
ISR can actually reach the flagged variable. In the Catapult RC624 firmware this
produced ~130 CON03-C FPs (76% of 176 total CON03-C hits). The rule does not build a
call graph to determine ISR reachability.

CON07-C update:
The Catapult audit confirms ~52 CON07-C FPs (80% of 65 total) from the same root
cause: main-loop-only functions flagged because their file contains an ISR.

Combined FP mass from both rules in one real-world MCU firmware: ~182 Medium findings,
all from the same root cause (no ISR reachability analysis).

Decision options (unchanged from original task 151 framing):
  A. Demote/disable-by-default (original plan): eliminates noise, loses the ~8–24%
     genuine signal.
  B. ISR call-graph fix: build reachability before flagging. Eliminates FPs while
     preserving the ~26 genuine CON07-C + ~46 genuine CON03-C hits.

The Catapult numbers strengthen the case for option B if there is appetite to invest
in the call-graph infrastructure, since the FP rate on MCU firmware is very high.
ISR-name heuristic note: DEV_APPROX_IRQProcess in the Catapult codebase contains
"IRQ" in its name but is a main-loop polling function — name matching alone is
insufficient; vector-table or indirect-call analysis is needed as a supplement.
```

---

## UPDATE EXISTING TASK — Task 172 (ARR30-C FN detection)

```
Append to details of task 172:

--- 2026-06-17 Catapult audit update ---

The Catapult RC624 firmware produced ~109 ARR30-C FPs from two sub-patterns that
reinforce the case for the ARR30-C re-point already described in this task:

Sub-pattern A (~108 hits): enum-constant indices on arrays sized exactly to the enum
range (e.g., WIFI_Net_FunArray indexed by WIFI_NET_IDLE, WIFI_NET_CONF, etc. where
the array is sized to WIFI_NET_END). sqc cannot prove cross-TU enum→array-size
alignment. This FP mass goes away entirely if the ARR30-C trigger is replaced with
taint-aware unbounded-read detection (the main thrust of task 172).

Sub-pattern B (1–2 hits): sqc miscounts AdcChannelTable in dev_adc.c as having 5
elements when the actual declaration has 11 — likely because only one `#if` branch's
initializer list is counted. This is a secondary array-size inference bug; if the
old trigger is kept for a transition period, the size-counting logic should aggregate
across `#if`/`#else` branches before comparing.

Both sub-patterns are resolved by task 172's proposed new trigger; no separate task
is needed. Sub-pattern B is also addressed by the `#if 0` preprocessor task above if
that work extends to conditional compilation in array initializers.
```
