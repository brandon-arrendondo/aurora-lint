/* The other side of aurora_lint 1448: narrowing the mark to the assigned
 * path must not stop the assigned path itself from dangling.
 *
 * The raw count here goes 5 (base) -> 4 (fix), which looks like a loss and
 * is not. Read the findings, not the total:
 *
 *   base  12:3  "returning freed pointer 'h'"          misattributed
 *         12:10 "accessing member of freed 'h'" TWICE  misattributed + duped
 *         19    NOTHING -- the real double free is MISSED
 *         27    the identifier case, correct
 *
 *   fix   12:10 "accessing freed pointer 'h->head'"    correctly attributed
 *         19:3  "Double-free: 'h->head'"               NEWLY CAUGHT
 *         27    unchanged
 *
 * Base marked the container `h` and never marked `h->head`, so it could not
 * see the second free of that member. Narrowing the mark to the assigned
 * path fixes the attribution AND recovers the detection. */
#include <stdlib.h>

typedef struct Rec { int n; struct Rec *next; } Rec;
typedef struct { Rec *head; int count; } Holder;

/* The member that received the dangling pointer is still dangling. */
int assigned_member_dangles(Holder *h, Rec *p) {
  free(p);
  h->head = p;
  return h->head->n;
}

/* Freeing through the member that received it is a double free. */
void assigned_member_freed_again(Holder *h, Rec *p) {
  free(p);
  h->head = p;
  free(h->head);
}

/* A plain identifier LHS is unchanged: the path IS the root. */
int identifier_alias_still_dangles(Rec *q) {
  Rec *p;
  free(q);
  p = q;
  return p->n;
}
