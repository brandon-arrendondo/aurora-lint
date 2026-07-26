/*
 * Rule: EXP44-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

void f(void) {
  int * volatile v;
  (void)sizeof(*v);
}