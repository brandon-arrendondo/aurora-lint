/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - one arm defines the callee and the other only declares it, so a build calls a function with no body to read
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

#ifdef USE_LOCAL
static void h(struct conn *c) {
  c->engine = NULL;
}
#else
extern void h(struct conn *c);
#endif

void conn_free(struct conn *c) {
  free(c->ssl);
  h(c);
  free(c);
}
