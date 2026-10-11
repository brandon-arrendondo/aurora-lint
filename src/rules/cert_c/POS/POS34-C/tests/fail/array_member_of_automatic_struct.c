/*
 * Rule: POS34-C
 * Source: CERT POS34-C text (automatic storage)
 * Status: FAIL - an array member of an automatic struct
 */

#include <stdlib.h>

struct entry {
  int tag;
  char text[64];
};

int func(const char *var) {
  struct entry e;
  snprintf(e.text, sizeof(e.text), "TEST=%s", var);
  return putenv(e.text);
}
