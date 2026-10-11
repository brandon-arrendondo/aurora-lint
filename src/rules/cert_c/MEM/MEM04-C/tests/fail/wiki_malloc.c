/*
 * Rule: MEM04-C
 * Source: wiki
 * Status: FAIL - Should trigger MEM04-C violation
 *
 * CERT's noncompliant example, as a function: size arrives from the
 * caller ("possibly by user-controlled input") and is not checked for zero.
 */

#include <stdlib.h>

int *make_list(size_t size)
{
  int *list = (int *)malloc(size);
  if (list == NULL) {
    /* Handle allocation error */
  }
  else {
  /* Continue processing list */
  }
  return list;
}
