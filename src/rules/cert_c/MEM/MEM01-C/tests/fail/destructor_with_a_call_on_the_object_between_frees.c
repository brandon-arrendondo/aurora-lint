/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the object holding the freed member is handed to a function before it is freed itself, and that function can read the member
 */

#include <stdlib.h>

struct reader {
  char *term;
  char *node;
};

extern int root_only(struct reader *);

void reader_free(struct reader *r) {
  free(r->term);
  if (!root_only(r)) {
    free(r->node);
  }
  free(r);
}
