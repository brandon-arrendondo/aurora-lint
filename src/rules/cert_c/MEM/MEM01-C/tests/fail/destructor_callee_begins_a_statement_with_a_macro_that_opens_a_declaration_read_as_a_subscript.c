/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - a macro at the start of a statement in the callee opens an array declaration the parser reads as a subscript; the declaration shadows the file's typedef, and the callee reads through the object it declares
 */

#include <stdlib.h>
#include <stdio.h>
struct conn { char *ssl; char *engine; };
typedef int log_conn;
void set_log(struct conn *c);
#define DECL_LOG struct conn *log_conn
#define LOG_TARGET log_conn
extern struct conn *gc;
static void conn_log(struct conn *c) {
  DECL_LOG[1];
  c->engine = NULL;
  if (LOG_TARGET[0]) puts(LOG_TARGET[0]->ssl);
}

void conn_free(struct conn *c) {
  set_log(c);
  free(c->ssl);
  conn_log(c);
  free(c);
}
