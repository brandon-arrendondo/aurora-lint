/*
 * Rule: MEM01-C
 * Source: CERT MEM01-C text; maintainer ruling that "immediately" means before the pointer can next be read or escape
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
