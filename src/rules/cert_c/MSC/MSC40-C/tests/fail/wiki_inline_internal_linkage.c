/*
 * Rule: MSC40-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC40-C violation
 * Expect: count=1
 */

static int I = 12;
extern inline void func(int a) {
  int b = a * I; /* Expect: here */
  /* ... */
}