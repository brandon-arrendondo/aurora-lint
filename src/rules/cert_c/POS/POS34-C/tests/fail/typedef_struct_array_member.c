/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: FAIL - the array member of a typedef'd automatic struct
 */

#include <stdlib.h>

typedef struct {
  char buf[16];
} S;

void run(void) {
  S s = {"A=1"};
  putenv(s.buf);
}
