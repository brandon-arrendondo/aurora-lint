/*
 * Rule: MEM01-C
 * Source: Maintainer ruling, rulings walk-through Q40 (MEM01-C)
 * Status: FAIL - C23 free_sized frees its first argument
 */

#include <stdlib.h>

int release_sized(char *p, size_t n) {
  free_sized(p, n);
  return p != NULL;
}
