/*
 * Rule: INT02-C
 * Source: regression
 * Status: PASS - two exact-width 8-bit signed operands
 *
 * int8_t is exactly 8 bits on every target that has it, and int is at least
 * 16, so 127 * 127 = 16129 fits INT_MAX wherever the code is built.
 */

#include <stdint.h>

int small_product(int8_t a, int8_t b) {
  return a * b;
}
