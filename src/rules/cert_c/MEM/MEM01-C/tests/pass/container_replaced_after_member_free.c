/*
 * Rule: MEM01-C
 * Source: Maintainer ruling, rulings walk-through Q40 (MEM01-C)
 * Status: PASS - storing to the holding pointer ends the member's path
 */

#include <stdlib.h>

struct item {
  char *buf;
  struct item *next;
};

void drop_buffers(struct item *s) {
  while (s) {
    free(s->buf);
    s = s->next;
  }
}
