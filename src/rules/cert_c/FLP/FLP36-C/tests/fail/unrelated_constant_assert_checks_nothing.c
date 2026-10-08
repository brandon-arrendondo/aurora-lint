/*
 * Rule: FLP36-C
 * Source: regression
 * Status: VIOLATION under every preset
 *
 * Both asserts are constant, but neither names an integer limit or a
 * floating-point precision, so neither checks whether the conversion below
 * is exact: `BUF_SIZE > 0` is about a buffer, and `1` checks nothing.
 */

#include <assert.h>

#define BUF_SIZE 64

float to_float(long big) {
  assert(BUF_SIZE > 0);
  assert(1);
  float approx = big;
  return approx;
}
