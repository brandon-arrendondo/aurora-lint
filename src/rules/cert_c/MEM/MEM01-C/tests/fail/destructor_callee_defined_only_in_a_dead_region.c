/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the only definition of the callee is under `#if 0`, so the call reaches a function this file does not define
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

extern void h(struct conn *c);
#if 0
void h(struct conn *c) {
  c->engine = NULL;
}
#endif

void conn_free(struct conn *c) {
  free(c->ssl);
  h(c);
  free(c);
}
