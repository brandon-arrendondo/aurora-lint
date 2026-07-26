/*
 * Rule: FLP34-C
 * Source: wiki
 * Status: FAIL - Should trigger FLP34-C violation
 */

void func(float f_a) {
  int i_a;
 
  /* Undefined if the integral part of f_a cannot be represented. */
  i_a = f_a;
}