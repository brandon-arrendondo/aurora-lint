/*
 * Rule: INT31-C
 * Source: wiki
 * Status: EXPECTED FAIL - Known limitation: LONG_MAX provably does not fit a
 * signed char, but INT31-C has no value-based definite-truncation channel
 * ahead of its provenance gate (INT30-C and INT32-C both have one), so a
 * local initialised from a constant reads as bounded local state. A
 * genuine INT31-C violation.
 */

#include <limits.h>

void func(void) {
  signed long int s_a = LONG_MAX;
  signed char sc = (signed char)s_a; /* Cast eliminates warning */
  /* ... */
}