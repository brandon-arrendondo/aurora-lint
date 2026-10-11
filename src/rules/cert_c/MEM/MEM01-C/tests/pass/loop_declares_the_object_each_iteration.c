/*
 * Rule: MEM01-C
 * Source: Maintainer ruling, rulings walk-through Q40 (MEM01-C)
 * Status: PASS - each iteration declares a new object, so the next read is not of the freed member
 */

#include <stdlib.h>

struct buf {
  char *data;
  int n;
};

void retry(struct buf *pending, int rounds) {
  while (rounds--) {
    struct buf cons = *pending;
    if (cons.data) {
      pending->n = cons.n;
    }
    free(cons.data);
  }
}
