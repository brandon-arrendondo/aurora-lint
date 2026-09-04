/*
 * Rule: INT08-C
 * Source: wiki (adapted)
 * Status: PASS - Should NOT trigger INT08-C violation
 *
 * CERT's canonical noncompliant example for this pattern declares `i` as a
 * plain `int` and warns that `if (i + 1 <= i)` is an unreliable overflow
 * check: it tests for overflow using the very expression that overflowed,
 * which the compiler is free to optimize away since signed overflow is UB.
 *
 * This file used to adapt that example to `short` on the theory that it
 * still belonged to INT08-C's narrow-type scope in this codebase. It
 * doesn't: `i` promotes to `int` before `i + 1` is evaluated, and no
 * `short`/`char` value (nor two of them combined via `+` or `-`) can push a
 * >=32-bit promoted `int` out of range (task 755) -- so this file no longer
 * represents an INT08-C violation as scoped here. The unreliable-check
 * *pattern* CERT is actually warning about (testing for overflow with an
 * expression that already overflowed) is a distinct concern from "can this
 * arithmetic overflow at all", and isn't something this rule claims to
 * detect.
 */

void foo(void) {
  short i = 32767;
  if (i + 1 <= i) {
    /* This check pattern is unreliable/UB-prone in general, but the
     * underlying `i + 1` cannot itself overflow here: promoted to int,
     * 32768 fits comfortably in a (>=32-bit) int. */
  }
}
