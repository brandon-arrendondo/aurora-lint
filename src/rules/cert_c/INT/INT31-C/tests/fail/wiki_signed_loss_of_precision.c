/*
 * Rule: INT31-C
 * Source: wiki
 * Status: DETECTED. Was expected_fail until the value-based channels gained
 * interval division/remainder, a compound-assignment arm, a
 * definitely-negative left shift, and -- for INT31-C -- a definite-truncation
 * channel of its own. The operands here are compile-time known and the
 * operation provably misbehaves, so it is reported whatever their provenance.
 */

#include <limits.h>

void func(void) {
  signed long int s_a = LONG_MAX;
  signed char sc = (signed char)s_a; /* Cast eliminates warning */
  /* ... */
}