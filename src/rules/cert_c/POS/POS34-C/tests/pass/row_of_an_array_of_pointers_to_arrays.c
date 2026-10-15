/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: PASS - ps[0] is a pointer, so ps[0][1] is a row of an array elsewhere
 */

#include <stdlib.h>

void run(char (*heap)[16]) {
  char (*ps[2])[16] = {heap, heap};
  putenv(ps[0][1]);
}
