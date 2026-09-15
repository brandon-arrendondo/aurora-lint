/*
 * Rule: EXP05-C
 * Source: regression
 * Status: FAIL - Should trigger EXP05-C violation
 *
 * memset's destination is a non-const pointer parameter, so passing a
 * const-qualified object there does cast const away. Exact-name resolution
 * must still find a local declaration.
 */

#include <string.h>

void wipe(void) {
  const unsigned char secret[16] = {0};

  memset(secret, 0, sizeof(secret));
}
