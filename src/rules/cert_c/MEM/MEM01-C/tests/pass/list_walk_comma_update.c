/*
 * Rule: MEM01-C
 * Source: CERT MEM01-C text; maintainer ruling that "immediately" means before the pointer can next be read or escape
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
