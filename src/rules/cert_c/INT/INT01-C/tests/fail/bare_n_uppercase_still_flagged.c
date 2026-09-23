/*
 * Rule: INT01-C
 * Source: real-world (recall-preservation guard: a bare single-letter size
 *   parameter, upper or lower case - as in sqlite's tool/showjournal.c
 *   read_content(int N, ...) - must still be flagged)
 * Status: FAIL - Should trigger INT01-C violation
 */
#include <stddef.h>

void *malloc(size_t sz);

unsigned char *read_content(int N) {
  return (unsigned char *)malloc(N);
}
