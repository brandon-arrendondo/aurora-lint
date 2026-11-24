/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 * Expect: count=1
 *
 * The operand of `sizeof` is evaluated when its type is a variable length
 * array (C11 6.5.3.4p2), so `p->n` in `sizeof(char[p->n])` dereferences
 * `p` on the path where it is null.
 */
#include <stddef.h>

struct buf {
  size_t n;
};

size_t span(struct buf *p) {
  if (p == NULL) {
    return sizeof(char[p->n]);
  }
  return p->n;
}
