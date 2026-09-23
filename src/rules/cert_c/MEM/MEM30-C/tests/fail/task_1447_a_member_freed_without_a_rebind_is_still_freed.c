/* The other side of aurora_lint 1447: only a rebind of the path the member
 * hangs off retargets it. Each function below is a real defect. */
#include <stdlib.h>

typedef struct { char *a; int n; } Blob;
typedef struct { Blob block; Blob key; int iBlock; } NodeWriter;
typedef struct { NodeWriter aNodeWriter[4]; } Writer;

/* No rebind anywhere: a plain double free of the same member. */
void no_rebind(Writer *w) {
  NodeWriter *p = &w->aNodeWriter[0];
  free(p->block.a);
  free(p->block.a);
}

/* Writing a SIBLING member does not retarget block.a -- `p->key.a` is not
 * a prefix of `p->block.a`, so the freed mark must survive. */
void sibling_member_assigned(Writer *w, char *fresh) {
  NodeWriter *p = &w->aNodeWriter[0];
  free(p->block.a);
  p->key.a = fresh;
  free(p->block.a);
}

/* Freeing the member itself and then reading it is still a use-after-free:
 * nothing was rebound, the member just got freed. */
int read_after_free(Writer *w) {
  NodeWriter *p = &w->aNodeWriter[0];
  free(p->block.a);
  return p->block.a[0];
}
