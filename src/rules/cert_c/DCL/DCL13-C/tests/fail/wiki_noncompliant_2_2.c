/*
 * Rule: DCL13-C
 * Source: wiki
 * Status: FAIL - Should trigger DCL13-C violation
 */

void foo(const int *x) {
  if (x != NULL) {
    *x = 3; /* Compiler should generate diagnostic message */
  }
  /* ... */
}