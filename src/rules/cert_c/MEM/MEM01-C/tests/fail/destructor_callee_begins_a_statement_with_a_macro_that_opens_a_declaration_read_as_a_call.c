/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - a macro at the start of a statement in the callee opens a declaration whose initializer the parser reads as a call's arguments; the declaration shadows the file's typedef, and the callee reads through the object it declares
 */

#include <stdlib.h>
#include <stdio.h>
struct conn { char *engine; char *ssl; };
typedef int log_conn;
#define DECL_LOG struct conn *log_conn = (struct conn *)(void *)
#define LOG_TARGET log_conn
static void conn_log(struct conn *c) {
  DECL_LOG (c->engine);
  if (LOG_TARGET) puts(LOG_TARGET->ssl);
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_log(c);
  free(c);
}
