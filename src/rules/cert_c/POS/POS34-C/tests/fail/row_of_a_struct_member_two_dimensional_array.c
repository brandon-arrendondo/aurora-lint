/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: FAIL - r.rows[0] is a row of an array member of an automatic struct
 */

#include <stdlib.h>

struct R {
  char rows[2][16];
};

void run(void) {
  struct R r = {{"A=1", "B=2"}};
  putenv(r.rows[0]);
}
