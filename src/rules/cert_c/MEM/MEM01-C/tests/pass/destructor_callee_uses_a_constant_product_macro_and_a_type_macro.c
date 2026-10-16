/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - the callee's macros are a product of constants used as an operand and a type made of keywords used as a declaration's type; neither can declare or read anything, so the callee leaves the freed member alone
 */

#include <stdlib.h>

struct conn {
  char *ssl;
  char *engine;
  unsigned area;
};

#define WIDTH 3
#define HEIGHT 4
#define AREA WIDTH * HEIGHT
#define u8 unsigned char

static void conn_reset(struct conn *c) {
  u8 shift = 1;
  c->engine = NULL;
  c->area = AREA << shift;
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_reset(c);
  free(c);
}
