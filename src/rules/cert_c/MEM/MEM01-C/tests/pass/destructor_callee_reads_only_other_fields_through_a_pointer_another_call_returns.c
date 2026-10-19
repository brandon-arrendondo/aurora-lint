/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - the pointer the callee gets from another function is used only for a field other than the freed one
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
  struct conn *peer;
};

void set_log(struct conn *c);
struct conn *get_log(void);

static void conn_log(struct conn *c) {
  struct conn *log_conn = get_log();
  c->engine = NULL;
  if (log_conn) puts(log_conn->engine);
}

void conn_free(struct conn *c) {
  set_log(c);
  free(c->ssl);
  conn_log(c);
  free(c);
}
