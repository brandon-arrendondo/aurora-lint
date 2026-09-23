/*
 * Rule: INT02-C
 * Source: wiki
 * Status: EXPECTED_FAIL - real defect this rule does not yet detect
 *
 * A genuine defect -- max is 128 and a signed char cannot reach it, so the
 * loop never terminates -- but NOT a signed/unsigned comparison one: char and
 * unsigned char both promote to int, so the comparison itself is
 * signed-vs-signed. Catching it needs range reasoning about the loop counter,
 * not conversion typing.
 */

#include <limits.h>

unsigned char max = CHAR_MAX + 1;
for (char i = 0; i < max; ++i) {
  printf("i=0x%08x max=0x%08x\n", i, max);
}