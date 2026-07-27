/*
 * Rule: DCL13-C
 * Source: wiki
 * Status: PASS - Should NOT trigger DCL13-C violation. x is already
 * const-qualified; this snippet illustrates the (unrelated) compiler
 * diagnostic for attempting to write through a const pointer, not a
 * "should have been const but isn't" case DCL13-C itself targets. Was
 * previously duplicated into tests/fail/ with a contradictory FAIL
 * expectation by the scraper; that copy is removed.
 */

void foo(const int *x) {
  if (x != NULL) {
    *x = 3; /* Compiler should generate diagnostic message */
  }
  /* ... */
}