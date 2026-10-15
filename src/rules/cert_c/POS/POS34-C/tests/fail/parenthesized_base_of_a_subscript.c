/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: FAIL - the base of the subscript is not a bare identifier
 */

#include <stdlib.h>

void run(void) {
  char env[2][16] = {"A=1", "B=2"};
  putenv((env)[1]);
}
