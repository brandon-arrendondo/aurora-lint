/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - a statement in the callee that begins with a typedef name and a parenthesized declarator is a declaration the parser reads as an assignment to a call; it shadows the file's typedef that the macro expands to, and the callee reads through the object it declares
 */

#include <stdlib.h>
#include <stdio.h>
struct conn { char *ssl; char *engine; };
typedef struct conn *conn_p;
typedef int log_conn;
void set_log(struct conn *c);
struct conn *get_log(void);
#define LOG_TARGET log_conn
static void conn_log(struct conn *c) {
  conn_p (log_conn) = get_log();
  c->engine = NULL;
  if (LOG_TARGET) puts(LOG_TARGET->ssl);
}

void conn_free(struct conn *c) {
  set_log(c);
  free(c->ssl);
  conn_log(c);
  free(c);
}
