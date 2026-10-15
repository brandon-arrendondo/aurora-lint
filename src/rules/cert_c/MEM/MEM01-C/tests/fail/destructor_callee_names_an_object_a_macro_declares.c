/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee names a file-scope pointer that a macro's expansion declares, where the caller stored the object
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

#define DECLARE_LOG_TARGET struct conn *log_conn;
DECLARE_LOG_TARGET

static void conn_log(struct conn *c) {
  c->engine = NULL;
  if (log_conn) puts(log_conn->ssl);
}

void conn_free(struct conn *c) {
  log_conn = c;
  free(c->ssl);
  conn_log(c);
  free(c);
}
