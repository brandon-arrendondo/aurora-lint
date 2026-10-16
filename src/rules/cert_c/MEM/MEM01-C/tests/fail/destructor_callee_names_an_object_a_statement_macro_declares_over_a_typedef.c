/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - a macro used as a statement in the callee declares a block-scope extern object by a name the file's typedef makes a type; the object is set outside the scan, and the callee reads the freed member through it
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

typedef int log_conn;

void set_log(struct conn *c);

#define USE_LOG extern struct conn *log_conn
#define LOG_TARGET log_conn

static void conn_log(struct conn *c) {
  USE_LOG;
  c->engine = NULL;
  if (LOG_TARGET) puts(LOG_TARGET->ssl);
}

void conn_free(struct conn *c) {
  set_log(c);
  free(c->ssl);
  conn_log(c);
  free(c);
}
