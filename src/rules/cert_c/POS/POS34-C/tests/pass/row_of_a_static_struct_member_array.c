/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: PASS - the struct is static, so its array member and the rows of it are too
 */

#include <stdlib.h>

struct R {
  char rows[2][16];
};

void run(void) {
  static struct R r = {{"A=1", "B=2"}};
  putenv(r.rows[0]);
}
