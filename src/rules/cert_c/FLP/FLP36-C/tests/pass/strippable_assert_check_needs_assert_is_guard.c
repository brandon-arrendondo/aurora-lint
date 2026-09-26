/*
 * Rule: FLP36-C
 * Source: regression
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * An assert mentioning LONG_MAX in the function counts as a precision check
 * under the default policy (assert_is_guard). The strict policy reads the
 * release configuration, where NDEBUG strips the assert and nothing checks
 * the conversion (ADR-0010 D5).
 */

#include <assert.h>
#include <limits.h>

float to_float(long big) {
  assert(big <= LONG_MAX);
  float approx = big;
  return approx;
}
