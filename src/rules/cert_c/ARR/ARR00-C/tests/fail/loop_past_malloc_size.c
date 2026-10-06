/* The loop bound exceeds the malloc size read back from the allocation call. */

#include <stdlib.h>

void fill(void)
{
  int *p = malloc(10 * sizeof(int));
  if (p == NULL) {
    return;
  }
  for (int i = 0; i < 15; i++) {
    p[i] = 0;
  }
  free(p);
}
