/*
 * Rule: INT02-C
 * Source: wiki
 * Status: PASS - Should NOT trigger INT02-C violation
 */

#include <stdio.h>

void func(int si, unsigned int ui) {
  printf("%d\n", (si < 0 || (unsigned)si < ui));
}
