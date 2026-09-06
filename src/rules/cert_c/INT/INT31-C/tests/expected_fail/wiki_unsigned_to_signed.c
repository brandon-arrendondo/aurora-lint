/*
 * Rule: INT31-C
 * Source: wiki
 * Status: EXPECTED FAIL, by measurement rather than oversight. INT31-C now has a
 * definite-truncation channel, but it cannot evaluate this operand: the
 * converted value is ULONG_MAX, and ValueRange is i64-based, so 2^64-1 is
 * unrepresentable. The builtin limit table therefore has no unsigned 64-bit
 * entries, and saturating one in would put a knowingly-wrong constant in front
 * of every rule that evaluates constants. Genuine violation; kept as evidence.
 */

#include <limits.h>
 
void func(void) {
  unsigned long int u_a = ULONG_MAX;
  signed char sc;
  sc = (signed char)u_a; /* Cast eliminates warning */
  /* ... */
}