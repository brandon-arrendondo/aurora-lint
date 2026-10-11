/*
 * Rule: MEM01-C
 * Source: Maintainer ruling, rulings walk-through Q40 (MEM01-C)
 * Status: PASS - the for update stores to p before the condition reads it
 */

#include <stdlib.h>

struct node {
  struct node *next;
};

void free_list(struct node *head) {
  struct node *p, *next;
  for (p = head; p; p = next) {
    next = p->next;
    free(p);
  }
}
