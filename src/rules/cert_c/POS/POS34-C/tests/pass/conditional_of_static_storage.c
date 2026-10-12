/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: PASS - neither arm is automatic
 */

#include <stdlib.h>

void run(int k) {
  static char env[16] = "A=1";
  putenv(k ? env : "B=2");
}
