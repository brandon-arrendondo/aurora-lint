/*
 * Rule: INT32-C
 * Source: wiki
 * Status: DETECTED. Was expected_fail until the provenance gate learned to
 * read a parameter's provenance off its callers rather than treating every
 * parameter as bounded local state. No caller of this function is visible in
 * the scan set, so its parameters carry unbounded input and the arithmetic is
 * reported.
 */

void func(signed int si_a, signed int si_b) {
  signed int sum = si_a + si_b;
  /* ... */
}