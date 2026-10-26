/*
 * Rule: MSC40-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger MSC40-C violation
 *
 * `LOCAL` expands to `static`, so this inline definition has internal
 * linkage and the constraint does not govern it.
 */

#define LOCAL static

LOCAL inline unsigned next_value(void) {
  static unsigned counter = 1;
  return counter++;
}
