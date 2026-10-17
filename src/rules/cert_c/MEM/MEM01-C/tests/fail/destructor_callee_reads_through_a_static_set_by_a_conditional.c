/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the static the callee's macro names is set to the object in a conditional's arm, which is no constant
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct conn {
  char *ssl;
  char *engine;
};

static struct conn *log_target;
#define LOG_TARGET log_target

static void conn_log(struct conn *c) {
  c->engine = NULL;
  if (LOG_TARGET) {
    puts(LOG_TARGET->ssl);
  }
}

void conn_free(struct conn *c) {
  log_target = c->engine ? c : NULL;
  free(c->ssl);
  conn_log(c);
  free(c);
}
