/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - a macro in a declaration's type position declares a block-scope extern object by a name the file's typedef makes a type; the callee reads the freed member through it
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

typedef int log_conn;

void set_log(struct conn *c);

#define LOG_DECLS extern struct conn *log_conn; int
#define LOG_TARGET log_conn

static void conn_log(struct conn *c) {
  LOG_DECLS unused = 0;
  c->engine = NULL;
  if (LOG_TARGET) puts(LOG_TARGET->ssl);
  (void)unused;
}

void conn_free(struct conn *c) {
  set_log(c);
  free(c->ssl);
  conn_log(c);
  free(c);
}
