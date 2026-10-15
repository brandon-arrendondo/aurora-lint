/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - a macro declares a static of this file that is only ever set to NULL, and the callee's macro names it
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct conn {
  char *ssl;
  char *engine;
};

#define DECLARE_LOG_TARGET static struct conn *log_target;
DECLARE_LOG_TARGET
#define LOG_TARGET log_target

void log_reset(void) {
  log_target = NULL;
}

static void conn_log(struct conn *c) {
  c->engine = NULL;
  if (LOG_TARGET) {
    puts("logging");
  }
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_log(c);
  free(c);
}
