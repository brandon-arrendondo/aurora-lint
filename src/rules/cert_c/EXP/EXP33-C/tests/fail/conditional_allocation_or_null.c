/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * A conditional whose other arm is a null pointer constant: wherever p
 * points at memory, that memory came from malloc and holds nothing yet.
 */

#include <stdlib.h>

char conditional_allocation(size_t n) {
    char *p = n ? malloc(n) : NULL;
    char c = p[0]; /* VIOLATION */
    free(p);
    return c;
}
