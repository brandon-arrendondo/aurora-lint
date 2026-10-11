/*
 * Rule: MEM04-C
 * Source: wiki
 * Status: PASS - Should NOT trigger MEM04-C violation
 *
 * CERT's compliant solution, as a function: the error handling for a zero
 * size leaves before the allocation.
 */

#include <stdlib.h>

int *make_list(size_t size)
{
  if (size == 0) {
    /* Handle error */
    return NULL;
  }
  int *list = (int *)malloc(size);
  if (list == NULL) {
    /* Handle allocation error */
  }
  /* Continue processing list */
  return list;
}
