/*
 * Rule: MEM01-C
 * Source: CERT MEM01-C text; maintainer ruling that "immediately" means before the pointer can next be read or escape
 * Status: FAIL - C23 free_sized frees its first argument
 */

#include <stdlib.h>

int release_sized(char *p, size_t n) {
  free_sized(p, n);
  return p != NULL;
}
