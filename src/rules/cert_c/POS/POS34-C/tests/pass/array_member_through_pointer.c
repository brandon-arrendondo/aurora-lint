/*
 * Rule: POS34-C
 * Source: CERT POS34-C text (automatic storage)
 * Status: PASS - a member reached through a pointer is the caller's storage
 */

#include <stdlib.h>

struct entry {
  char text[64];
};

int func(struct entry *e) {
  return putenv(e->text);
}
