/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee's macro names an object with external linkage, which another translation unit may write
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct conn {
  char *ssl;
  char *engine;
};

struct conn *log_target;
#define LOG_TARGET log_target

static void conn_log(struct conn *c) {
  c->engine = NULL;
  if (LOG_TARGET) {
    puts("logging");
  }
}

void conn_free(struct conn *c) {
  log_target = NULL;
  free(c->ssl);
  conn_log(c);
  free(c);
}
