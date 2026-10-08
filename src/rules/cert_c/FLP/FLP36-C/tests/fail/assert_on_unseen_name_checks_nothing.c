/*
 * Rule: FLP36-C
 * Source: regression
 * Status: VIOLATION under every preset
 *
 * `g_limit` comes from a header the scan does not see, so nothing says it is a
 * constant rather than a global whose value may change: the assert is not a
 * precision check (flp36_constant_assert_is_guard credits only constants the
 * file can see).
 */

#include <assert.h>
#include "board_config.h"

float to_float(long big) {
  assert(g_limit < 100);
  float approx = big;
  return approx;
}
