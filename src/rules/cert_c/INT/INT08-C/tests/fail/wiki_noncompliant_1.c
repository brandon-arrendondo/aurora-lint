/*
 * Rule: INT08-C
 * Source: wiki (adapted)
 * Status: FAIL - Should trigger INT08-C violation
 *
 * CERT's canonical noncompliant example for this pattern declares `i` as a
 * plain `int` and warns that `if (i + 1 <= i)` is an unreliable overflow
 * check: it tests for overflow using the very expression that overflowed,
 * which the compiler is free to optimize away since signed overflow is UB.
 * That's adapted here to `short` so it falls within this rule's scope --
 * INT08-C in this codebase targets narrow-type (char/short) promotion
 * footguns specifically, while INT32-C covers overflow on int/long/etc.
 * (see int08_c.rs's is_narrow_integer_type doc comment).
 *
 * Note this adaptation means no *actual* signed-overflow UB fires in
 * `i + 1` itself: `i` promotes to `int` before the addition, and 32768
 * fits comfortably in a (typically 32-bit) int. The violation here is the
 * unreliable check *pattern* -- the same anti-pattern CERT flags -- not a
 * claim that this specific width/value combination invokes UB.
 */

void foo(void) {
  short i = 32767;
  if (i + 1 <= i) {
    /* Handle overflow -- but this check pattern is unreliable/UB-prone
     * in general, per CERT INT08-C */
  }
}
