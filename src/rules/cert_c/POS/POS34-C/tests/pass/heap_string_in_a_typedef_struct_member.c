/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: PASS - the argument is a heap string reached through a typedef'd struct pointer member
 */

#include <stdlib.h>
#include <string.h>

typedef struct {
  char *entry;
} S;

void run(void) {
  S s;
  s.entry = strdup("A=1");
  putenv(s.entry);
}
