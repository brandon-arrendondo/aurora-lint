# Juliet C Test Suite — Coverage Report

**Version**: aurora-lint v0.4.336 (sqc-0.4.336-0e8b74e7)
**Overall**: 23,577 TP / 3,818 FP — **86.1% TP rate** across 79 CWEs (50,256 files)

*Auto-generated from sqc_bench Postgres (run sqc-0.4.336-0e8b74e7) by benchmarking_db's bin/refresh_juliet_coverage.py -- see tools_sqc's CLAUDE.md on why this is the only path that may write this file as a project measurement.*

---

## 100% Precision (41 CWEs — zero FP)

| CWE | Description | TP | Files | Per-File |
|-----|------------|---:|------:|--------:|
| CWE-327 | Use Broken Crypto | 54 | 54 | 100.0% |
| CWE-467 | Use of sizeof on Pointer Type | 54 | 54 | 100.0% |
| CWE-188 | Reliance on Data Memory Layout | 36 | 36 | 100.0% |
| CWE-273 | Improper Check for Dropped Privileges | 36 | 36 | 100.0% |
| CWE-367 | TOC TOU | 36 | 36 | 100.0% |
| CWE-469 | Use of Pointer Subtraction to Determine Size | 36 | 36 | 100.0% |
| CWE-242 | Use of Inherently Dangerous Function | 18 | 18 | 100.0% |
| CWE-338 | Weak PRNG | 18 | 18 | 100.0% |
| CWE-479 | Signal Handler Use of Non Reentrant Function | 54 | 18 | 100.0% |
| CWE-480 | Use of Incorrect Operator | 18 | 18 | 100.0% |
| CWE-481 | Assigning Instead of Comparing | 18 | 18 | 100.0% |
| CWE-482 | Comparing Instead of Assigning | 18 | 18 | 100.0% |
| CWE-587 | Assignment of Fixed Address to Pointer | 18 | 18 | 100.0% |
| CWE-685 | Function Call With Incorrect Number of Arguments | 18 | 18 | 100.0% |
| CWE-562 | Return of Stack Variable Address | 2 | 2 | 100.0% |
| CWE-666 | Operation on Resource in Wrong Phase of Lifetime | 162 | 90 | 100.0% |
| CWE-459 | Incomplete Cleanup | 34 | 36 | 94.4% |
| CWE-226 | Sensitive Information Uncleared Before Release | 68 | 72 | 94.4% |
| CWE-244 | Heap Inspection | 98 | 72 | 94.4% |
| CWE-758 | Undefined Behavior | 342 | 365 | 93.7% |
| CWE-563 | Unused Variable | 272 | 366 | 74.3% |
| CWE-398 | Poor Code Quality | 125 | 181 | 69.1% |
| CWE-464 | Addition of Data Structure Sentinel | 38 | 56 | 67.9% |
| CWE-591 | Sensitive Data Storage in Improperly Locked Memory | 74 | 112 | 66.1% |
| CWE-253 | Incorrect Check of Function Return Value | 432 | 684 | 63.2% |
| CWE-426 | Untrusted Search Path | 132 | 224 | 58.9% |
| CWE-468 | Incorrect Pointer Scaling | 18 | 36 | 50.0% |
| CWE-561 | Dead Code | 1 | 2 | 50.0% |
| CWE-674 | Uncontrolled Recursion | 1 | 2 | 50.0% |
| CWE-680 | Integer Overflow to Buffer Overflow | 379 | 336 | 46.4% |
| CWE-761 | Free Pointer Not at Start of Buffer | 276 | 672 | 41.1% |
| CWE-843 | Type Confusion | 40 | 100 | 40.0% |
| CWE-197 | Numeric Truncation Error | 556 | 1008 | 37.8% |
| CWE-195 | Signed to Unsigned Conversion Error | 610 | 1344 | 36.3% |
| CWE-789 | Uncontrolled Mem Alloc | 190 | 560 | 33.9% |
| CWE-681 | Incorrect Conversion Between Numeric Types | 17 | 54 | 31.5% |
| CWE-78 | OS Command Injection | 2810 | 5600 | 30.2% |
| CWE-590 | Free Memory Not on Heap | 240 | 900 | 26.7% |
| CWE-194 | Unexpected Sign Extension | 400 | 1344 | 23.8% |
| CWE-252 | Unchecked Return Value | 144 | 630 | 22.9% |
| CWE-114 | Process Control | 126 | 672 | 18.8% |

## High Precision (>50% TP rate, 24 CWEs)

| CWE | Description | TP | FP | TP Rate | Per-File |
|-----|------------|---:|---:|--------:|--------:|
| CWE-191 | Integer Underflow | 1588 | 18 | 98.9% | 38.4% |
| CWE-134 | Uncontrolled Format String | 1650 | 30 | 98.2% | 49.1% |
| CWE-190 | Integer Overflow | 1995 | 57 | 97.2% | 36.9% |
| CWE-665 | Improper Initialization | 68 | 4 | 94.4% | 30.4% |
| CWE-457 | Use of Uninitialized Variable | 506 | 31 | 94.2% | 82.1% |
| CWE-675 | Duplicate Operations on Resource | 80 | 6 | 93.0% | 35.7% |
| CWE-416 | Use After Free | 367 | 36 | 91.1% | 92.0% |
| CWE-690 | NULL Deref From Return | 648 | 67 | 90.6% | 54.8% |
| CWE-127 | Buffer Underread | 720 | 100 | 87.8% | 31.6% |
| CWE-122 | Heap Based Buffer Overflow | 1495 | 291 | 83.7% | 32.2% |
| CWE-404 | Improper Resource Shutdown | 222 | 60 | 78.7% | 49.6% |
| CWE-775 | Missing Release of File Descriptor or Handle | 74 | 20 | 78.7% | 44.0% |
| CWE-121 | Stack Based Buffer Overflow | 2518 | 848 | 74.8% | 37.4% |
| CWE-124 | Buffer Underwrite | 652 | 268 | 70.9% | 34.4% |
| CWE-272 | Least Privilege Violation | 292 | 128 | 69.5% | 100.0% |
| CWE-391 | Unchecked Error Condition | 55 | 32 | 63.2% | 100.0% |
| CWE-773 | Missing Reference to Active File Descriptor or Handle | 34 | 20 | 63.0% | 20.2% |
| CWE-476 | NULL Pointer Dereference | 394 | 235 | 62.6% | 86.6% |
| CWE-369 | Divide by Zero | 544 | 330 | 62.2% | 54.0% |
| CWE-415 | Double Free | 468 | 288 | 61.9% | 67.9% |
| CWE-126 | Buffer Overread | 168 | 118 | 58.7% | 12.2% |
| CWE-401 | Memory Leak | 862 | 685 | 55.7% | 59.8% |
| CWE-377 | Insecure Temporary File | 114 | 96 | 54.3% | 75.0% |
| CWE-364 | Signal Handler Race Condition | 36 | 34 | 51.4% | 100.0% |

## Medium Precision (33–50% TP rate, 1 CWEs)

| CWE | Description | TP | FP | TP Rate | Per-File |
|-----|------------|---:|---:|--------:|--------:|
| CWE-319 | Cleartext Tx Sensitive Info | 8 | 16 | 33.3% | 3.6% |

## Low Precision (<33% TP rate, 0 CWEs)

| CWE | Description | TP | FP | TP Rate | Per-File |
|-----|------------|---:|---:|--------:|--------:|

## Zero Detection (9 CWEs)

| CWE | Description | Files | Notes |
|-----|------------|------:|-------|
| CWE-123 | Write What Where Condition | 168 | No rule mapped |
| CWE-259 | Hard Coded Password | 112 | No rule mapped |
| CWE-321 | Hard Coded Cryptographic Key | 112 | No rule mapped |
| CWE-176 | Improper Handling of Unicode Encoding | 56 | No rule mapped |
| CWE-328 | Reversible One Way Hash | 54 | No rule mapped |
| CWE-366 | Race Condition Within Thread | 36 | No rule mapped |
| CWE-667 | Improper Locking | 18 | No rule mapped |
| CWE-570 | Expression Always False | 16 | No rule mapped |
| CWE-571 | Expression Always True | 16 | No rule mapped |

*4 additional CWEs had no test files: CWE-23, CWE-672, CWE-676, CWE-762.*

## Top Rules by TP Volume

| Rule | TP | FP | FP Rate | Primary CWEs |
|------|---:|---:|--------:|-------------|
| INT32-C | 3,010 | 0 | 0.0% | CWE-190, CWE-191, CWE-680 |
| ARR38-C | 2,142 | 648 | 23.2% | CWE-121, CWE-127, CWE-124 |
| ARR30-C | 1,803 | 699 | 27.9% | CWE-122, CWE-121, CWE-126, CWE-124 |
| FIO30-C | 1,650 | 30 | 1.8% | CWE-134 |
| STR31-C | 1,608 | 278 | 14.7% | CWE-121, CWE-122, CWE-124, CWE-127 |
| ENV33-C | 1,550 | 0 | 0.0% | CWE-78 |
| INT31-C | 1,299 | 0 | 0.0% | CWE-195, CWE-194, CWE-197 |
| EXP34-C | 976 | 212 | 17.8% | CWE-690, CWE-476 |
| EXP33-C | 914 | 35 | 3.7% | CWE-457, CWE-758, CWE-665 |
| MEM31-C | 862 | 685 | 44.3% | CWE-401 |
| ENV03-C | 832 | 0 | 0.0% | CWE-78, CWE-426 |
| INT30-C | 633 | 18 | 2.8% | CWE-190, CWE-191, CWE-680 |
| ERR33-C | 613 | 32 | 5.0% | CWE-253, CWE-252, CWE-391 |
| STR02-C | 560 | 0 | 0.0% | CWE-78 |
| MEM30-C | 451 | 162 | 26.4% | CWE-416, CWE-415 |
| INT33-C | 420 | 204 | 32.7% | CWE-369 |
| MEM01-C | 366 | 144 | 28.2% | CWE-415, CWE-416 |
| FIO42-C | 364 | 100 | 21.6% | CWE-404, CWE-775, CWE-773, CWE-459 |
