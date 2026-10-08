/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * Every configuration counts (ADR-0010): without ZERO_BUFFERS, buf_alloc
 * is malloc, so the block is uninitialized in that build.
 */

#include <stdlib.h>

#ifdef ZERO_BUFFERS
#define buf_alloc(n) calloc(1, n)
#else
#define buf_alloc(n) malloc(n)
#endif

char one_build_uninitialized(void) {
    char *p = buf_alloc(8);
    char c = p[0]; /* VIOLATION */
    free(p);
    return c;
}
