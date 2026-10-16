/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - a macro expanding to a pointer declarator declares an extern object by the name the file's typedef makes a type, and the callee reads the freed member through it
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

typedef int log_conn;

void set_log(struct conn *c);

#define LOG_PTR *log_conn
#define LOG_TARGET log_conn

static void conn_log(struct conn *c) {
  extern struct conn LOG_PTR;
  c->engine = NULL;
  if (LOG_TARGET) puts(LOG_TARGET->ssl);
}

void conn_free(struct conn *c) {
  set_log(c);
  free(c->ssl);
  conn_log(c);
  free(c);
}
