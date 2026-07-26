/*
 * Rule: INT34-C
 * Source: wiki
 * Status: FAIL - Should trigger INT34-C violation
 */

void func(unsigned int ui_a, unsigned int ui_b) {
  unsigned int uresult = ui_a >> ui_b;
  /* ... */
}