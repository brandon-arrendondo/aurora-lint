/*
 * Rule: MSC30-C
 * Source: testcases
 * Status: PASS - rand is a project macro, so the call is not the standard
 * library's rand()
 */

#include <stdint.h>

uint32_t csprng_u32(void);

#define rand() ((int)(csprng_u32() & 0x7fffffff))

int pick(void) {
  return rand();
}
