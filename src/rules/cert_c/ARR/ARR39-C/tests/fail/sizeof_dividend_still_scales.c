/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: FAIL - Should trigger ARR39-C violation
 * Expect: count=3
 *
 * A scaled byte count stays one when it is the dividend, or when a
 * dividing sizeof sits beside a multiplying one, so adding it to an int
 * pointer scales twice.
 */

#include <stddef.h>

int *half_way(int *ptr, size_t n) {
  return ptr + n * sizeof(int) / 2;
}

int *past_header(int *ptr, size_t len) {
  return ptr + len / sizeof(int) + sizeof(long);
}

int *advance(int *ptr, size_t n) {
  ptr += (n * sizeof(int)) / 2;
  return ptr;
}
