/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: PASS - a row of a static 3-D array outlives the function
 */

#include <stdlib.h>

void run(void) {
  static char env[2][2][16] = {{"A=1", "B=2"}, {"C=3", "D=4"}};
  putenv(env[0][1]);
}
