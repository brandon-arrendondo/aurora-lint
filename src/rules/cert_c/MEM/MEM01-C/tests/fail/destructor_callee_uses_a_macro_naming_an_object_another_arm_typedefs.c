/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee's object-like macro names an object the caller stores the object in; a typedef of the same name in another #if arm does not make the name a type where the callee compiles
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

#ifdef OLD_LOG
typedef int log_conn;
#else
struct conn *log_conn;
#endif

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
