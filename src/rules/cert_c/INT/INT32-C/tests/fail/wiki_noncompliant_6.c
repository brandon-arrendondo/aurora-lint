/*
 * Rule: INT32-C
 * Source: wiki
 * Status: DETECTED. Was expected_fail until the provenance gate learned to
 * read a parameter's provenance off its callers rather than treating every
 * parameter as bounded local state. No caller of this function is visible in
 * the scan set, so its parameters carry unbounded input and the arithmetic is
 * reported.
 */

#include <limits.h>
#include <stddef.h>
#include <inttypes.h>
 
extern size_t popcount(uintmax_t);
#define PRECISION(umax_value) popcount(umax_value) 

void func(signed long si_a, signed long si_b) {
  signed long result;
  if ((si_a < 0) || (si_b < 0) ||
      (si_b >= PRECISION(ULONG_MAX))) {
    /* Handle error */
  } else {
    result = si_a << si_b;
  } 
  /* ... */
}