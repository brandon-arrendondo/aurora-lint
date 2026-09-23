/* A loop whose condition is a non-NULL test of `p` can only reach the code
 * after it, other than by `break`, by failing that test -- so `p` is NULL
 * there, and the last iteration's free(p) leaves nothing dangling.
 *
 * sqlite's vdbesort.c frees each record in a `for(p=...; p; p=pNext)` loop
 * and then stores `p` back into the list head; that stores NULL. */
#include <stdlib.h>

typedef struct Rec { int n; struct Rec *next; } Rec;
typedef struct { Rec *head; } List;

/* The sqlite shape: bare-identifier condition, writeback, then a read. */
void writeback_after_for(List *l) {
  Rec *p, *pNext;
  for (p = l->head; p; p = pNext) {
    pNext = p->next;
    free(p);
  }
  l->head = p;
  if (l->head) l->head->n = 0;
}

/* `p != NULL`. */
Rec *for_not_equal_null(Rec *p) {
  Rec *pNext;
  for (; p != NULL; p = pNext) {
    pNext = p->next;
    free(p);
  }
  return p;
}

/* `NULL != p`. */
Rec *for_null_not_equal(Rec *p) {
  Rec *pNext;
  for (; NULL != p; p = pNext) {
    pNext = p->next;
    free(p);
  }
  return p;
}

/* while: the body's last act on `p` is a free. */
Rec *while_body_ends_in_free(Rec *p, Rec *q) {
  while (p) {
    free(p);
    p = q;
    q = 0;
    free(p);
  }
  return p;
}

/* do-while: the test at the bottom proves the same. */
Rec *do_body_ends_in_free(Rec *p, Rec *q) {
  do {
    free(p);
    p = q;
    q = 0;
    free(p);
  } while (p);
  return p;
}

/* A `continue` re-tests the condition, so it leaves with `p` NULL too. */
Rec *continue_retests_the_condition(Rec *p, int k) {
  Rec *pNext;
  for (; p; p = pNext) {
    pNext = p->next;
    free(p);
    if (k) continue;
    k++;
  }
  return p;
}

/* A `break` inside a switch ends the switch, not the loop. */
Rec *switch_break_is_not_a_loop_break(Rec *p, int k) {
  Rec *pNext;
  for (; p; p = pNext) {
    pNext = p->next;
    switch (k) {
    case 1:
      free(p);
      break;
    default:
      free(p);
      break;
    }
  }
  return p;
}
