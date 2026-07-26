/*
 * Rule: MSC21-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

void f(size_t begin, size_t step) {
  if (0 < step) {
    size_t i;
    for (i = begin; i <= SIZE_MAX - step; i += step) {
      /* ... */
    }
  }
}