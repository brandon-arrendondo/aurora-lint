/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS under the default and strict presets; VIOLATION under pedantic
 * Expect: default=clean strict=clean pedantic=violation
 *
 * `p` is null on the path where `flag` is zero. free(NULL) does nothing in
 * a hosted environment (C11 7.22.3.3p2), so the default and strict presets
 * trust the call. The pedantic preset trusts only a declared library, and
 * this fixture declares none, so nothing says this free() tolerates NULL.
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
