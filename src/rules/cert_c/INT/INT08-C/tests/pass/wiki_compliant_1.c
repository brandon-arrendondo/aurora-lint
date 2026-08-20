/*
 * Rule: INT08-C
 * Source: wiki
 * Status: PASS - Should NOT trigger INT08-C violation
 */

void foo(void) {
  long i = 32767;
  /* No test is necessary; i is known not to overflow */
  long j = i + 1;
  (void)j;
}