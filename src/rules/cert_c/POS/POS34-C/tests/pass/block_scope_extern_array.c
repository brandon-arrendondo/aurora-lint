/*
 * Rule: POS34-C
 * Source: CERT POS34-C text (automatic storage)
 * Status: PASS - a block-scope extern declaration names static storage
 */

#include <stdlib.h>

char shared_env[1024];

int func(void) {
  extern char shared_env[];
  return putenv(shared_env);
}
