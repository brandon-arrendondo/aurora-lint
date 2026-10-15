/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee is defined only under a conditional and the caller is outside it, so a build calls a function this file does not define
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

#if defined(USE_LOCAL)
static void h(struct conn *c) {
  c->engine = NULL;
}
#endif

void conn_free(struct conn *c) {
  free(c->ssl);
  h(c);
  free(c);
}
