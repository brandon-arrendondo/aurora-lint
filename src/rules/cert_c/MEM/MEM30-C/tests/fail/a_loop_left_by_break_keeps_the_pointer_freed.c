/* The other side of the loop-exit NULL refinement: a `break` leaves the
 * loop WITHOUT testing its condition, so `p` can still be non-NULL and
 * freed after the loop. Only the condition-failing exits prove `p` NULL;
 * every finding in this file comes from a break exit, and must survive.
 * If the NULL refinement is ever applied to break exits too, this file
 * goes clean. */
#include <stdlib.h>

typedef struct Rec { int n; struct Rec *next; } Rec;

/* for: freed, then break -- `p` is dangling after the loop. */
Rec *break_after_free_in_for(Rec *p, int k) {
  Rec *pNext;
  for (; p; p = pNext) {
    pNext = p->next;
    free(p);
    if (k) break;
  }
  return p;
}

/* while with `p != NULL`: the break skips the test. */
int break_after_free_in_while(Rec *p) {
  while (p != NULL) {
    if (p->n == 3) {
      free(p);
      break;
    }
    p = p->next;
  }
  return p->n;
}
