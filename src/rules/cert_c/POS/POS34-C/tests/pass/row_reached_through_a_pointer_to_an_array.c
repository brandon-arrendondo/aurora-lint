/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: PASS - the rows live in the heap block the pointer points at
 */

#include <stdlib.h>

void run(void) {
  char (*rows)[16] = malloc(2 * sizeof *rows);
  if (rows != NULL) {
    putenv(rows[1]);
  }
}
