/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee reads `doclist.data`, the freed member itself, through the object it is handed
 */

#include <stdlib.h>

struct doclist {
  char *data;
  int n;
};

struct phrase {
  struct doclist doclist;
  int invalid;
};

static void invalidate(struct phrase *p) {
  p->invalid = p->doclist.data != 0;
}

void phrase_cleanup(struct phrase *p) {
  free(p->doclist.data);
  invalidate(p);
  free(p);
}
