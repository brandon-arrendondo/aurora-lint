/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - the callee's macros name a static level of this file that is only ever set to enumeration and macro constants and stepped, so it cannot hold the object, and the object is freed next
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct conn {
  char *ssl;
  char *engine;
};

enum level { LEVEL_OFF, LEVEL_ON };
#define LEVEL_DEFAULT (LEVEL_ON * 2)
static int log_level = LEVEL_OFF;
#define LOG_LEVEL_NOW log_level
#define LOG_LEVEL (LOG_LEVEL_NOW)

void log_enable(void) {
  log_level = LEVEL_DEFAULT;
  log_level++;
  log_level += 2;
}

static void conn_log(struct conn *c) {
  c->engine = NULL;
  if (LOG_LEVEL > 1) {
    puts("closing");
  }
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_log(c);
  free(c);
}
