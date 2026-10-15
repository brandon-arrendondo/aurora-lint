/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the caller stores the object in a member of a file-scope struct and the callee reads the freed member through it
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

static struct {
  struct conn *cur;
} g_state;

static void h(struct conn *c) {
  c->engine = NULL;
  if (g_state.cur->ssl) puts(g_state.cur->ssl);
}

void conn_free(struct conn *c) {
  g_state.cur = c;
  free(c->ssl);
  h(c);
  free(c);
}
