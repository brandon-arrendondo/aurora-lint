/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - the freed member is nested (`phrase->doclist.data`) and the callee, defined under a conditional that also holds the caller, reads a sibling of it (`doclist.n`) and never `doclist.data`
 */

#include <stdlib.h>

struct doclist {
  char *data;
  int n;
};

struct phrase {
  struct doclist doclist;
  int ntoken;
  int invalid;
};

#if !defined(OMIT_PHRASES)
static void invalidate(struct phrase *p) {
  p->invalid = p->ntoken > 0 || p->doclist.n > 0;
}

void phrase_cleanup(struct phrase *p) {
  free(p->doclist.data);
  invalidate(p);
  free(p);
}
#endif
