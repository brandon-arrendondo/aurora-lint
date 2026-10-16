/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - a statement in the callee that begins with a typedef name has a macro as its parenthesized declarator, which the parser reads as a call's argument; the declaration shadows the file's typedef the macros expand to, and the callee reads through the object it declares
 */

#include <stdlib.h>
#include <stdio.h>
struct conn { char *ssl; char *engine; };
typedef struct conn *conn_p;
typedef int log_conn;
void set_log(struct conn *c);
struct conn *get_log(void);
#define DECL log_conn
#define LOG_TARGET log_conn
static void conn_log(struct conn *c) {
  conn_p (DECL) = get_log();
  c->engine = NULL;
  if (LOG_TARGET) puts(LOG_TARGET->ssl);
}

void conn_free(struct conn *c) {
  set_log(c);
  free(c->ssl);
  conn_log(c);
  free(c);
}
