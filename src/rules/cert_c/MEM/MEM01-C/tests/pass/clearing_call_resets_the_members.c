/*
 * Rule: MEM01-C
 * Source: CERT MEM01-C text; maintainer ruling that "immediately" means before the pointer can next be read or escape
 * Status: PASS - a memset over the rest of the object resets the freed members
 */

#include <stdlib.h>
#include <string.h>

struct cursor {
  int flags;
  char *stat;
  char *stop;
};

void cursor_reset(struct cursor *c) {
  free(c->stat);
  free(c->stop);
  memset(&c->stat, 0, ((unsigned char *)&c[1]) - (unsigned char *)&c->stat);
}
