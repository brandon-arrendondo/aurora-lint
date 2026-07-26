/*
 * Rule: MSC21-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC21-C violation
 */

size_t i;
for (i = 1; i != 10; i += 2) {
  /* ... */
}