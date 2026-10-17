/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - a macro by the static's own name replaces it with the parameter, so the callee's macro reads the object
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
#define log_target (c)

static void conn_log(struct conn *c) {
  c->engine = NULL;
  if (LOG_TARGET) {
    puts(LOG_TARGET->ssl);
  }
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_log(c);
  free(c);
}
