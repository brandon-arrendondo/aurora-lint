/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee is defined in the #if arm and the call is in the #elif arm, so no build has both
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

#if defined(USE_ENGINE)
static void h(struct conn *c) {
  c->engine = NULL;
}
#elif defined(USE_OTHER)
void conn_free(struct conn *c) {
  free(c->ssl);
  h(c);
  free(c);
}
#else
void conn_noop(void) {}
#endif
