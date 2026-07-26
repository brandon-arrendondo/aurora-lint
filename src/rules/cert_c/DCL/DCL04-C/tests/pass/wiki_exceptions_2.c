/*
 * Rule: DCL04-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <limits.h>  /* For CHAR_BIT */
#include <stddef.h>  /* For size_t   */
 
extern size_t popcount(uintmax_t);
#define PRECISION(umax_value) popcount(umax_value) 

 size_t bitcount(size_t n) {
  const size_t limit = PRECISION(SIZE_MAX);
  size_t count = 0;
  for (size_t i = 0, j = 1; i < limit; ++i, j <<= 1) {
    if (n & j)
      ++count;
  }
  return count;
}