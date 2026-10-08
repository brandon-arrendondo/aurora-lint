/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * An object-like alias renames an allocator without any text spelling it:
 * get_block(8) is malloc(8), so the block it returns is uninitialized.
 */

#include <stdlib.h>

#define get_block malloc

char through_alias(void) {
    char *p = get_block(8);
    char c = p[0]; /* VIOLATION */
    free(p);
    return c;
}
