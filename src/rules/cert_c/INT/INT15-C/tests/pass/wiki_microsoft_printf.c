/*
 * Rule: INT15-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <stdio.h>
#include <inttypes.h>

mytypedef_t x;

/* ... */

#ifdef _MSC_VER
  printf("%llu", (uintmax_t) x);
#else
  printf("%ju", (uintmax_t) x);
#endif