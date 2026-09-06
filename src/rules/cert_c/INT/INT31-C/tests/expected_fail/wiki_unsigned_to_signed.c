/*
 * Rule: INT31-C
 * Source: wiki
 * Status: EXPECTED FAIL - Known limitation: ULONG_MAX provably does not fit a
 * signed char, but INT31-C has no value-based definite-truncation channel
 * ahead of its provenance gate (INT30-C and INT32-C both have one), so a
 * local initialised from a constant reads as bounded local state. A
 * genuine INT31-C violation.
 */

#include <limits.h>
 
void func(void) {
  unsigned long int u_a = ULONG_MAX;
  signed char sc;
  sc = (signed char)u_a; /* Cast eliminates warning */
  /* ... */
}