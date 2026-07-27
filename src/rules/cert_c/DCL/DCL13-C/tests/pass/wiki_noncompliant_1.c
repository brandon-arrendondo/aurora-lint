/*
 * Rule: DCL13-C
 * Source: wiki
 * Status: PASS - Should NOT trigger DCL13-C violation. This wiki snippet is
 * illustrative prose (explaining why unmodified pointer params should be
 * const), not a standalone violation instance: x is genuinely modified
 * (*x = 3), so leaving it non-const is correct per this rule's own logic
 * (confirmed against testcases_modified_params.c / testcases_unmodified_
 * pointer_params.c). Was previously duplicated into tests/fail/ with a
 * contradictory FAIL expectation by the scraper; that copy is removed.
 */

void foo(int *x) {
  if (x != NULL) {
    *x = 3; /* Visible outside function */
  }
  /* ... */
}