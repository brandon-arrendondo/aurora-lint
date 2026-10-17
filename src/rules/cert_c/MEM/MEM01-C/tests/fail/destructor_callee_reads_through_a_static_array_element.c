/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee's macro names an element of a static array that holds the object, and an array's elements are stored without assigning the array
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct conn {
  char *ssl;
  char *engine;
};

static struct conn *log_targets[2];
#define LOG_TARGET log_targets[0]

static void conn_log(struct conn *c) {
  c->engine = NULL;
  if (LOG_TARGET) {
    puts(LOG_TARGET->ssl);
  }
}

void conn_free(struct conn *c) {
  struct conn **slot = log_targets;
  *slot = c;
  free(c->ssl);
  conn_log(c);
  free(c);
}
