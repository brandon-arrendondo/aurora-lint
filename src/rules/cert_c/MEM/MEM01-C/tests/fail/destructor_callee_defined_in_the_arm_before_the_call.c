/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee is defined in the #ifdef arm and the call is in the #else arm, so no build has both
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

#ifdef USE_ENGINE
static void h(struct conn *c) {
  c->engine = NULL;
}
#else
void conn_free(struct conn *c) {
  free(c->ssl);
  h(c);
  free(c);
}
#endif
