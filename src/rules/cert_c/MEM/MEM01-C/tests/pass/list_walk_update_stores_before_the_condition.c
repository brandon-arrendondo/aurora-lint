/*
 * Rule: MEM01-C
 * Source: CERT MEM01-C text; maintainer ruling that "immediately" means before the pointer can next be read or escape
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
