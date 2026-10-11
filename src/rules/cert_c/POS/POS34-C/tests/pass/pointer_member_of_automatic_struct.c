/*
 * Rule: POS34-C
 * Source: CERT POS34-C text (automatic storage)
 * Status: PASS - a pointer member is not the struct's own storage
 */

#include <stdlib.h>

struct entry {
  char *text;
};

int func(char *heap) {
  struct entry e;
  e.text = heap;
  return putenv(e.text);
}
