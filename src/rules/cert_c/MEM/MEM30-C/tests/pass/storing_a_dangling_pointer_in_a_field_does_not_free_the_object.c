/* Storing a dangling pointer into a member makes THAT MEMBER dangle. The
 * object holding it was never freed, so its other members are untouched
 * .
 *
 * Before the fix the assignment marked the ROOT of the assigned lvalue, so
 * every unrelated sibling read came back as a use-after-free of the
 * container itself. */
#include <stdlib.h>

typedef struct Rec { int n; struct Rec *next; } Rec;
typedef struct { Rec *head; int count; char *name; } Holder;

/* `h` is not freed by any of this -- only h->head goes stale. */
int sibling_members_are_untouched(Holder *h, Rec *p) {
  free(p);
  h->head = p;
  return h->count;
}

/* Same, through a second sibling of a different type. */
char *another_sibling(Holder *h, Rec *p) {
  free(p);
  h->head = p;
  return h->name;
}
