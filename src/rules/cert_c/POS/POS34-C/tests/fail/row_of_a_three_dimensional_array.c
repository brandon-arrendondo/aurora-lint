/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: FAIL - env[0][1] is a char[16] row inside an automatic 3-D array
 */

#include <stdlib.h>

void run(void) {
  char env[2][2][16] = {{"A=1", "B=2"}, {"C=3", "D=4"}};
  putenv(env[0][1]);
}
