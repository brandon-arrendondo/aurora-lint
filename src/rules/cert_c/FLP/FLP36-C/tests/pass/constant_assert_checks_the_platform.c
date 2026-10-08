/*
 * Rule: FLP36-C
 * Source: regression
 * Status: PASS under the default and strict presets; VIOLATION under pedantic
 * Expect: default=clean strict=clean pedantic=violation
 *
 * The assert compares constants only, one of them a standard limit, so its
 * condition has the same value in every build for one target: a build that
 * strips it is no less safe than the one that checked it, in the spirit of
 * CERT's compliant solution (flp36_constant_assert_is_guard). The pedantic
 * policy credits no strippable check at all.
 */

#include <assert.h>
#include <limits.h>

#define FLOAT_EXACT_MAX 16777216L

float to_float(long big) {
  assert(LONG_MAX <= FLOAT_EXACT_MAX);
  float approx = big;
  return approx;
}
