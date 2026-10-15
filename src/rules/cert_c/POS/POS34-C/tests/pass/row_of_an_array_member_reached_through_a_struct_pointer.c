/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: PASS - p->rows is in the object p points at, not in the frame
 */

#include <stdlib.h>

struct R {
  char rows[2][16];
};

void run(struct R *p) {
  putenv(p->rows[0]);
}
