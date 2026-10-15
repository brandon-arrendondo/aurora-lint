/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee's object-like macro expands to a file-scope pointer, where the caller may have stored the object
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

struct conn *log_conn;
#define LOG_TARGET log_conn

static void conn_log(struct conn *c) {
  c->engine = NULL;
  if (LOG_TARGET) puts(LOG_TARGET->ssl);
}

void conn_free(struct conn *c) {
  log_conn = c;
  free(c->ssl);
  conn_log(c);
  free(c);
}
