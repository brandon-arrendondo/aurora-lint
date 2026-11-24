/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * 256 stored in an unsigned char is 0, which is below the bound, so the
 * loop runs and dereferences the null pointer.
 */
#include <stddef.h>

void f(void) {
    int *p = NULL;
    unsigned char k;
    for (k = 256; k < 1; k++) {
        *p = 1;
    }
}
