/*
 * Rule: INT01-C
 * Source: task 1151 (recall-preservation guard: dropping the naive
 *   whole-text substring match for bare 'n' must not also drop genuine
 *   Hungarian-notation size locals like nBytes/nNew, ubiquitous in sqlite's
 *   src/malloc.c and src/func.c)
 * Status: FAIL - Should trigger INT01-C violation
 */
#include <stddef.h>

void *my_realloc(void *ptr, size_t newSize);

void grow(void *old) {
  int nBytes = 128;
  void *p = my_realloc(old, nBytes);
  (void)p;
}
