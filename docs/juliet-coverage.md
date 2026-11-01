# Juliet C Test Suite — Coverage Report

**Version**: aurora-lint v0.7.0 (sqc-0.7.0-78ed3fe09-default+closed-849b299516c9)
**Overall**: 23,758 TP / 6,551 FP — **78.4% TP rate** across 79 CWEs (51,334 files)

*Auto-generated from sqc_bench Postgres (run sqc-0.7.0-78ed3fe09-default+closed-849b299516c9) by benchmarking_db's bin/refresh_juliet_coverage.py -- see aurora-lint's CLAUDE.md on why this is the only path that may write this file as a project measurement.*

---

## 100% Precision (33 CWEs — zero FP)

| CWE | Description | TP | Files | Per-File |
|-----|------------|---:|------:|--------:|
| CWE-480 | Use of Incorrect Operator | 18 | 18 | 100.0% |
| CWE-481 | Assigning Instead of Comparing | 18 | 18 | 100.0% |
| CWE-482 | Comparing Instead of Assigning | 18 | 18 | 100.0% |
| CWE-587 | Assignment of Fixed Address to Pointer | 18 | 18 | 100.0% |
| CWE-685 | Function Call With Incorrect Number of Arguments | 36 | 18 | 100.0% |
| CWE-688 | Function Call With Incorrect Variable or Reference as Argument | 18 | 18 | 100.0% |
| CWE-562 | Return of Stack Variable Address | 2 | 2 | 100.0% |
| CWE-484 | Omitted Break Statement in Switch | 18 | 18 | 100.0% |
| CWE-666 | Operation on Resource in Wrong Phase of Lifetime | 162 | 90 | 100.0% |
| CWE-327 | Use Broken Crypto | 54 | 54 | 100.0% |
| CWE-467 | Use of sizeof on Pointer Type | 54 | 54 | 100.0% |
| CWE-367 | TOC TOU | 36 | 36 | 100.0% |
| CWE-469 | Use of Pointer Subtraction to Determine Size | 36 | 36 | 100.0% |
| CWE-475 | Undefined Behavior for Input to API | 36 | 36 | 100.0% |
| CWE-483 | Incorrect Block Delimitation | 38 | 20 | 100.0% |
| CWE-242 | Use of Inherently Dangerous Function | 36 | 18 | 100.0% |
| CWE-338 | Weak PRNG | 18 | 18 | 100.0% |
| CWE-479 | Signal Handler Use of Non Reentrant Function | 54 | 18 | 100.0% |
| CWE-226 | Sensitive Information Uncleared Before Release | 68 | 72 | 94.4% |
| CWE-244 | Heap Inspection | 98 | 72 | 94.4% |
| CWE-758 | Undefined Behavior | 342 | 365 | 93.7% |
| CWE-398 | Poor Code Quality | 143 | 181 | 79.0% |
| CWE-563 | Unused Variable | 272 | 366 | 74.3% |
| CWE-464 | Addition of Data Structure Sentinel | 76 | 56 | 67.9% |
| CWE-253 | Incorrect Check of Function Return Value | 432 | 684 | 63.2% |
| CWE-561 | Dead Code | 1 | 2 | 50.0% |
| CWE-591 | Sensitive Data Storage in Improperly Locked Memory | 56 | 112 | 50.0% |
| CWE-188 | Reliance on Data Memory Layout | 18 | 36 | 50.0% |
| CWE-366 | Race Condition Within Thread | 18 | 36 | 50.0% |
| CWE-468 | Incorrect Pointer Scaling | 18 | 36 | 50.0% |
| CWE-252 | Unchecked Return Value | 378 | 630 | 40.0% |
| CWE-681 | Incorrect Conversion Between Numeric Types | 17 | 54 | 31.5% |
| CWE-590 | Free Memory Not on Heap | 240 | 900 | 26.7% |

## High Precision (>50% TP rate, 31 CWEs)

| CWE | Description | TP | FP | TP Rate | Per-File |
|-----|------------|---:|---:|--------:|--------:|
| CWE-134 | Uncontrolled Format String | 1710 | 60 | 96.6% | 50.9% |
| CWE-404 | Improper Resource Shutdown | 168 | 6 | 96.6% | 37.5% |
| CWE-775 | Missing Release of File Descriptor or Handle | 56 | 2 | 96.6% | 33.3% |
| CWE-416 | Use After Free | 309 | 12 | 96.3% | 92.0% |
| CWE-665 | Improper Initialization | 68 | 4 | 94.4% | 30.4% |
| CWE-457 | Use of Uninitialized Variable | 506 | 31 | 94.2% | 82.1% |
| CWE-127 | Buffer Underread | 514 | 64 | 88.9% | 27.1% |
| CWE-773 | Missing Reference to Active File Descriptor or Handle | 16 | 2 | 88.9% | 9.5% |
| CWE-680 | Integer Overflow to Buffer Overflow | 256 | 36 | 87.7% | 52.4% |
| CWE-690 | NULL Deref From Return | 677 | 129 | 84.0% | 52.1% |
| CWE-197 | Numeric Truncation Error | 370 | 72 | 83.7% | 35.3% |
| CWE-401 | Memory Leak | 727 | 152 | 82.7% | 56.1% |
| CWE-272 | Least Privilege Violation | 254 | 64 | 79.9% | 100.0% |
| CWE-195 | Signed to Unsigned Conversion Error | 710 | 180 | 79.8% | 42.3% |
| CWE-191 | Integer Underflow | 1869 | 501 | 78.9% | 46.8% |
| CWE-190 | Integer Overflow | 2435 | 693 | 77.8% | 46.4% |
| CWE-78 | OS Command Injection | 1940 | 560 | 77.6% | 13.6% |
| CWE-122 | Heap Based Buffer Overflow | 2256 | 747 | 75.1% | 48.3% |
| CWE-121 | Stack Based Buffer Overflow | 2512 | 862 | 74.5% | 37.3% |
| CWE-194 | Unexpected Sign Extension | 500 | 180 | 73.5% | 29.8% |
| CWE-476 | NULL Pointer Dereference | 281 | 110 | 71.9% | 65.6% |
| CWE-426 | Untrusted Search Path | 184 | 84 | 68.7% | 64.3% |
| CWE-124 | Buffer Underwrite | 446 | 232 | 65.8% | 23.5% |
| CWE-415 | Double Free | 402 | 210 | 65.7% | 67.9% |
| CWE-675 | Duplicate Operations on Resource | 72 | 42 | 63.2% | 32.1% |
| CWE-369 | Divide by Zero | 580 | 342 | 62.9% | 57.5% |
| CWE-126 | Buffer Overread | 168 | 118 | 58.7% | 12.2% |
| CWE-377 | Insecure Temporary File | 228 | 192 | 54.3% | 75.0% |
| CWE-391 | Unchecked Error Condition | 74 | 64 | 53.6% | 100.0% |
| CWE-843 | Type Confusion | 110 | 96 | 53.4% | 68.0% |
| CWE-364 | Signal Handler Race Condition | 36 | 34 | 51.4% | 100.0% |

## Medium Precision (33–50% TP rate, 3 CWEs)

| CWE | Description | TP | FP | TP Rate | Per-File |
|-----|------------|---:|---:|--------:|--------:|
| CWE-674 | Uncontrolled Recursion | 2 | 2 | 50.0% | 100.0% |
| CWE-114 | Process Control | 456 | 636 | 41.8% | 67.9% |
| CWE-390 | Error Without Action | 19 | 32 | 37.3% | 25.0% |

## Low Precision (<33% TP rate, 0 CWEs)

| CWE | Description | TP | FP | TP Rate | Per-File |
|-----|------------|---:|---:|--------:|--------:|

## Zero Detection (12 CWEs)

| CWE | Description | Files | Notes |
|-----|------------|------:|-------|
| CWE-400 | Resource Exhaustion | 840 | No rule mapped |
| CWE-761 | Free Pointer Not at Start of Buffer | 672 | No rule mapped |
| CWE-789 | Uncontrolled Mem Alloc | 560 | No rule mapped |
| CWE-90 | LDAP Injection | 560 | No rule mapped |
| CWE-259 | Hard Coded Password | 112 | No rule mapped |
| CWE-321 | Hard Coded Cryptographic Key | 112 | No rule mapped |
| CWE-588 | Attempt to Access Child of Non Structure Pointer | 50 | No rule mapped |
| CWE-667 | Improper Locking | 18 | No rule mapped |
| CWE-832 | Unlock of Resource That is Not Locked | 18 | No rule mapped |
| CWE-196 | Unsigned to Signed Conversion Error | 18 | No rule mapped |
| CWE-478 | Missing Default Case in Switch | 18 | No rule mapped |
| CWE-570 | Expression Always False | 16 | No rule mapped |

## Top Rules by TP Volume

| Rule | TP | FP | FP Rate | Primary CWEs |
|------|---:|---:|--------:|-------------|
| INT32-C | 3,514 | 945 | 21.2% | CWE-190, CWE-191 |
| ARR38-C | 2,744 | 996 | 26.6% | CWE-121, CWE-122, CWE-127, CWE-124 |
| FIO30-C | 1,710 | 60 | 3.4% | CWE-134 |
| ARR30-C | 1,689 | 694 | 29.1% | CWE-122, CWE-121, CWE-126, CWE-124 |
| INT31-C | 1,538 | 432 | 21.9% | CWE-195, CWE-194, CWE-197 |
| STR31-C | 1,214 | 227 | 15.8% | CWE-121, CWE-122, CWE-242 |
| EXP33-C | 914 | 35 | 3.7% | CWE-457, CWE-758, CWE-665 |
| ENV03-C | 904 | 264 | 22.6% | CWE-78, CWE-426 |
| ERR33-C | 838 | 193 | 18.7% | CWE-253, CWE-252, CWE-690, CWE-391 |
| INT30-C | 811 | 222 | 21.5% | CWE-190, CWE-191, CWE-680 |
| EXP34-C | 806 | 110 | 12.0% | CWE-690, CWE-476 |
| MEM31-C | 727 | 152 | 17.3% | CWE-401 |
| ENV33-C | 660 | 240 | 26.7% | CWE-78, CWE-426 |
| STR02-C | 560 | 140 | 20.0% | CWE-78 |
| INT33-C | 456 | 216 | 32.1% | CWE-369 |
| WIN00-C | 456 | 636 | 58.2% | CWE-114 |
| MEM01-C | 366 | 144 | 28.2% | CWE-415, CWE-416 |
| MEM30-C | 345 | 78 | 18.4% | CWE-415, CWE-416 |
