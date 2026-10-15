/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: PASS - an array parameter is a pointer into the caller's storage
 */

#include <stdlib.h>

void run(char env[2][16]) {
  putenv(env[1]);
}
