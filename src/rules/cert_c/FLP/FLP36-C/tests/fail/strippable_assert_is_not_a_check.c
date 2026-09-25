/*
 * Rule: FLP36-C
 * Source: regression
 * Status: FAIL - Should trigger FLP36-C violation
 *
 * An assert mentioning LONG_MAX somewhere in the function used to mark the
 * whole function compliant. NDEBUG strips the assert, so in the release
 * configuration nothing checks the conversion (ADR-0010 D5), and this one
 * does not even test the value's precision.
 */

#include <assert.h>
#include <limits.h>

float to_float(long big) {
  assert(big <= LONG_MAX);
  float approx = big;
  return approx;
}
