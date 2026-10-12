/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: FAIL - a row of an automatic two-dimensional array
 */

#include <stdlib.h>

void run(void) {
  char env[2][16] = {"A=1", "B=2"};
  putenv(env[0]);
}
