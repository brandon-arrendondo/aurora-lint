/*
 * Rule: MEM01-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

void foo(void) {
  char *str;
  /* ... */
  free(str);
  return;
}