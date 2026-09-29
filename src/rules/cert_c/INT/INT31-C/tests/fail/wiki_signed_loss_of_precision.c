/*
 * Rule: INT31-C
 * Source: wiki
 * Status: DETECTED. Was expected_fail until the value-based channels gained
 * Settings: data_model=lp64
 *
 * The truncation is proven from LONG_MAX's value, which a declared model
 * fixes: ISO C alone allows a signed char wide enough to hold it.
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