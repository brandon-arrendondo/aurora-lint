/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the caller stores the object in a file-scope pointer and the callee reads the freed member through it
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

static struct conn *g_cur;

static void h(struct conn *c) {
  c->engine = NULL;
  if (g_cur->ssl) puts(g_cur->ssl);
}

void conn_free(struct conn *c) {
  g_cur = c;
  free(c->ssl);
  h(c);
  free(c);
}
