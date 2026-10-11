/*
 * Rule: MSC30-C
 * Source: testcases
 * Status: PASS - a parameter spelled rand calls whatever it points at
 */

int draw(int (*rand)(void)) {
  return rand();
}
