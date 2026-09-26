/*
 * Rule: EXP34-C
 * Source: wiki (adapted — use malloc instead of png_malloc for detectability)
 * CERT's example as written is expected_fail/wiki_noncompliant_1_verbatim.c.
 * Status: FAIL - Should trigger EXP34-C violation
 */

#include <stdlib.h>
#include <string.h>

void func(int length, const void *user_data) {
  char *chunkdata;
  chunkdata = (char *)malloc(length + 1);
  /* chunkdata may be NULL if malloc fails */
  memcpy(chunkdata, user_data, length);
}
