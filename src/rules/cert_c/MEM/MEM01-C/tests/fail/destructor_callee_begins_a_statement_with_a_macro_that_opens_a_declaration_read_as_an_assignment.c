/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - a macro at the start of a statement in the callee opens a declaration whose initializer the parser reads as an assignment; the declaration shadows the file's typedef, and the callee reads the object it was given through it
 */

#include <stdlib.h>
#include <stdio.h>
struct conn { char *ssl; char *engine; };
typedef int log_conn;
void set_log(struct conn *c);
struct conn *get_log(void);
#define DECL_LOG struct conn *log_conn
#define LOG_TARGET log_conn
static void conn_log(struct conn *c) {
  DECL_LOG = get_log();
  c->engine = NULL;
  if (LOG_TARGET) puts(LOG_TARGET->ssl);
}

void conn_free(struct conn *c) {
  set_log(c);
  free(c->ssl);
  conn_log(c);
  free(c);
}
