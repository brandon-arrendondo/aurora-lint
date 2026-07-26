/*
 * Rule: MSC21-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC21-C violation
 */

void f(size_t begin, size_t step) {
  size_t i;
  for (i = begin; i <= SIZE_MAX; i += step) {
    /* ... */
  }
}