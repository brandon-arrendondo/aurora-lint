/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * `p` is null on the path where `flag` is zero. free(NULL) does nothing in
 * a hosted environment (C11 7.22.3.3p2), so the default preset trusts the
 * call. The strict preset declares a freestanding environment with no
 * library model, where nothing says this free() tolerates NULL.
 */
#include <stdlib.h>

void release_optional(int flag)
{
    char *p = NULL;
    if (flag) {
        p = malloc(16);
    }
    free(p);
}
