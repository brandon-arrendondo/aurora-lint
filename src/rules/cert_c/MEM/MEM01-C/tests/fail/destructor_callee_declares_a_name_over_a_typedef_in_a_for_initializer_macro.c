/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - a macro in the callee's for-loop initializer declares an object by a name the file's typedef makes a type, so the callee's names are not all known and it is not proven to leave the member alone
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

typedef int log_conn;

#define LOG_CURSOR struct conn *log_conn = 0
#define LOG_TARGET log_conn

static void conn_log(struct conn *c) {
  c->engine = NULL;
  for (LOG_CURSOR; LOG_TARGET != 0;) {
    puts(LOG_TARGET->ssl);
    break;
  }
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_log(c);
  free(c);
}
