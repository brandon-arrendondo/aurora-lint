/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: FAIL - the array is a member of a struct that is a member of an automatic struct
 */

#include <stdlib.h>

struct Inner {
  char rows[2][16];
};

struct Outer {
  struct Inner inner;
};

void run(void) {
  struct Outer o = {{{"A=1", "B=2"}}};
  putenv(o.inner.rows[1]);
}
