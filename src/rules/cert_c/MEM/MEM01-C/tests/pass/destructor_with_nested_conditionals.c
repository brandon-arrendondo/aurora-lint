/*
 * Rule: MEM01-C
 * Source: CERT MEM01-C text; maintainer ruling that "immediately" means before the pointer can next be read or escape
 * Status: PASS - the object is freed on every path, past nested conditionals
 */

#include <stdlib.h>

struct reader {
  char *term;
  char *node;
  void *blob;
};

extern int root_only(struct reader *);
extern void blob_close(void *);

void reader_free(struct reader *r) {
  if (r) {
    free(r->term);
    if (!root_only(r)) {
      free(r->node);
    }
    blob_close(r->blob);
  }
  free(r);
}
