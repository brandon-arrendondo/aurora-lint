/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: FAIL - rs[1].buf is the array member of an element of an automatic array of structs
 */

#include <stdlib.h>

struct R {
  char buf[16];
};

void run(void) {
  struct R rs[2] = {{"A=1"}, {"B=2"}};
  putenv(rs[1].buf);
}
