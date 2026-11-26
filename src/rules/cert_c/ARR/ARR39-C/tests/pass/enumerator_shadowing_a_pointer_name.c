/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: PASS - Should not trigger ARR39-C violation
 *
 * An enumerator declared in a block makes its name a constant there,
 * whatever pointer the same name declares at file scope or as a
 * parameter. Adding a scaled integer to that constant is integer
 * arithmetic, not pointer arithmetic.
 */

#include <stddef.h>

extern int *g_buf;

long offset_of_table(size_t n) {
  enum { g_buf = 4 };
  return g_buf + n * sizeof(int);
}

long offset_of_slot(int *slot_buf, size_t n) {
  {
    enum { slot_buf = 1 };
    return slot_buf + n * sizeof(int);
  }
}
