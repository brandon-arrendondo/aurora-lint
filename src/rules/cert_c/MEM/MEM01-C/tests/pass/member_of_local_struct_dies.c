/*
 * Rule: MEM01-C
 * Source: Maintainer ruling, rulings walk-through Q40 (MEM01-C)
 * Status: PASS - a member of a local struct goes out of scope with it
 */

#include <stdlib.h>

struct pair {
  char *a;
  char *b;
};

void use_pair(void) {
  struct pair p;
  p.a = malloc(4);
  p.b = malloc(4);
  free(p.a);
  free(p.b);
}
