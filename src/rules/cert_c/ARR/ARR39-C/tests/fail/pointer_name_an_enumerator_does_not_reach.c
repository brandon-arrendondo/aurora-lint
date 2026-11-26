/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: FAIL - Should trigger ARR39-C violation
 * Expect: count=2
 *
 * An enumerator makes its name a constant only from its declaration to
 * the end of its block. Another function's block, or the same block before
 * the `enum`, still sees the pointer, so adding a scaled integer to it
 * scales twice.
 */

#include <stddef.h>

extern int *g_buf;

void setup(void) {
  enum { g_buf = 1 };
  (void)g_buf;
}

int *slot(size_t n) {
  return g_buf + n * sizeof(int);
}

long early(size_t n) {
  int *at = g_buf + n * sizeof(int);
  enum { g_buf = 2 };
  return (long)(at - (int *)0) + g_buf;
}
