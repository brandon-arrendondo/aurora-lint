/* Rebinding a pointer makes every path hanging off it name different
 * storage, so a free of the previous object's member is not a free of the
 * new one's.
 *
 * sqlite fts3_write.c's flush loop is the case this came from: each
 * iteration points pNode at the next array element and frees that
 * element's two buffers. */
#include <stdlib.h>

typedef struct { char *a; int n; } Blob;
typedef struct { Blob block; Blob key; int iBlock; } NodeWriter;
typedef struct { NodeWriter aNodeWriter[4]; } Writer;

/* Rebound by assignment: the second free targets a different element. */
void rebound_by_assignment(Writer *w) {
  NodeWriter *p = &w->aNodeWriter[0];
  free(p->block.a);
  p = &w->aNodeWriter[1];
  free(p->block.a);
}

/* Rebound by a fresh declaration inside the loop body -- the sqlite shape.
 *
 * Read this one honestly: it does NOT fire on the pre-fix binary with a
 * plain free(), because the declaration already cleared the base name and
 * nothing here reaches the paths under it a second time. It fires on the
 * real corpus only through aurora_lint 1441's guessed-free route, where
 * sqlite3_free is what does the freeing. It is kept because it is the
 * shape the task was filed from and it pins the loop form against
 * regression -- not because it demonstrates the pre-fix bug. The three
 * functions around it do that. */
void rebound_each_iteration(Writer *w, int iRoot) {
  int i;
  for (i = 0; i < iRoot; i++) {
    NodeWriter *p = &w->aNodeWriter[i];
    free(p->block.a);
    free(p->key.a);
  }
}

/* The rebound location is itself a field: paths inside it go stale too. */
typedef struct { NodeWriter *inner; } Holder;
void rebound_field(Holder *h, Writer *w) {
  free(h->inner->block.a);
  h->inner = &w->aNodeWriter[2];
  free(h->inner->block.a);
}

/* Setting the pointer to NULL retargets it just as plainly. */
void rebound_to_null(Writer *w, NodeWriter *q) {
  NodeWriter *p = &w->aNodeWriter[0];
  free(p->block.a);
  p = NULL;
  p = q;
  free(p->block.a);
}
