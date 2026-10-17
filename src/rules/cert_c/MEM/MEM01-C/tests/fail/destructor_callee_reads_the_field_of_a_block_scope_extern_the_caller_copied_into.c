/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee's block-scope extern names the global the destructor copied the object into, so reading ssl off it reads the freed address
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

static void conn_log(struct conn *c) {
  extern struct conn last_closed;
  c->engine = NULL;
  puts(last_closed.ssl);
}

void conn_free(struct conn *c) {
  extern struct conn last_closed;
  last_closed = *c;
  free(c->ssl);
  conn_log(c);
  free(c);
}
