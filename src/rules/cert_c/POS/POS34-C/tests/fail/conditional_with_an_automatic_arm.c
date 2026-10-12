/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: FAIL - one arm of the conditional is an automatic array
 */

#include <stdlib.h>

void run(int k) {
  char env[16] = "A=1";
  putenv(k ? env : "B=2");
}
