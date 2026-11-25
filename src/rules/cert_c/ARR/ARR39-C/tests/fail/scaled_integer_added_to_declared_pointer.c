/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: FAIL - Should trigger ARR39-C violation
 * Expect: count=3
 *
 * A scaled integer added to an operand whose declaration makes it a
 * pointer scales twice: to a local pointer, to an array, and through a
 * compound assignment.
 */

#include <stddef.h>

int sum_tail(int *buf, size_t n) {
  int *ptr = buf + n * sizeof(int);
  return *ptr;
}

int table_entry(size_t i) {
  static int data[64];
  return *(data + i * sizeof(int));
}

void advance(long *dest_ptr, size_t n) {
  dest_ptr += n * sizeof(long);
  *dest_ptr = 0;
}
