/*
 * Rule: MSC40-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC40-C violation
 * Expect: count=1
 */

extern inline void func(void) {
  static int I = 12; /* Expect: here */
  /* Perform calculations which may modify I */
}