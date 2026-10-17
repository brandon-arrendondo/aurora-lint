/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - inline assembly stores the object in the static the callee's macro names, which the parse cannot place
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
  __asm__ volatile("" : "=r"(log_target) : "0"(c));
  free(c->ssl);
  conn_log(c);
  free(c);
}
