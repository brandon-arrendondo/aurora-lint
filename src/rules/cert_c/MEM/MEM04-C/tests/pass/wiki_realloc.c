/*
 * Rule: MEM04-C
 * Source: wiki
 * Status: PASS - Should NOT trigger MEM04-C violation
 *
 * CERT's compliant solution, as a function: realloc runs only when nsize
 * is non-zero.
 */

#include <stdlib.h>

void *resize(char *p, size_t nsize)
{
  char *p2 = NULL;
  if (nsize != 0) {
    p2 = (char *)realloc(p, nsize);
  }
  if (p2 == NULL) {
    free(p);
    p = NULL;
    return NULL;
  }
  p = p2;
  return p;
}
