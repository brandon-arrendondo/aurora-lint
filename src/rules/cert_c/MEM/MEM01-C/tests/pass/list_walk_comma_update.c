/*
 * Rule: MEM01-C
 * Source: Maintainer ruling, rulings walk-through Q40 (MEM01-C)
 * Status: PASS - a comma in the for update stores to p first
 */

#include <stdlib.h>

struct node {
  struct node *next;
};

int free_list_counting(struct node *head) {
  struct node *p, *next;
  int n = 0;
  for (p = head; p; p = next, n++) {
    next = p->next;
    free(p);
  }
  return n;
}
