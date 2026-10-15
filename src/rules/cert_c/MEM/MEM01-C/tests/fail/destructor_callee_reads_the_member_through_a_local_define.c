/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee defines a macro for the freed member inside its body and reads through it
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

static void h(struct conn *c) {
#define S (c->ssl)
  if (S) puts(S);
#undef S
  c->engine = NULL;
}

void conn_free(struct conn *c) {
  free(c->ssl);
  h(c);
  free(c);
}
