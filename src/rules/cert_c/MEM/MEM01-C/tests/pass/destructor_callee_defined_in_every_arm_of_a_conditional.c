/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - the callee is defined in each arm of a conditional and neither body reads the freed member
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
static void h(struct conn *c) {
  if (c != NULL) c->engine = NULL;
}
#endif

void conn_free(struct conn *c) {
  free(c->ssl);
  h(c);
  free(c);
}
