/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: FAIL - Should trigger ARR39-C violation
 * Expect: count=9
 *
 * A scaled byte count stays one when it is the dividend, when a dividing
 * sizeof sits beside a multiplying one, or when it is what is left over
 * from a remainder, so adding it to an int pointer scales twice. How the
 * sizeof is spaced does not matter.
 */

#include <stddef.h>

int *half_way(int *ptr, size_t n) {
  return ptr + n * sizeof(int) / 2; /* Expect: here */
}

int *past_header(int *ptr, size_t len) {
  return ptr + len / sizeof(int) + sizeof(long); /* Expect: here */
}

int *advance(int *ptr, size_t n) {
  ptr += (n * sizeof(int)) / 2; /* Expect: here */
  return ptr;
}

int *spaced_product(int *ptr, size_t n) {
  return ptr + n * sizeof (int); /* Expect: here */
}

int *spaced_step(int *ptr, size_t n) {
  ptr += n * sizeof (int); /* Expect: here */
  return ptr;
}

int *spaced_parenthesized(int *ptr, size_t n) {
  return ptr + (n * sizeof (int)); /* Expect: here */
}

int *spaced_constant(int *ptr) {
  return ptr + 2 * sizeof (long); /* Expect: here */
}

int *leftover_bytes(int *ptr, size_t len) {
  return ptr + len % sizeof(int); /* Expect: here */
}

char *char_size_spaced(char *buf, size_t n) {
  return buf + n * sizeof (char); /* Expect: here */
}
