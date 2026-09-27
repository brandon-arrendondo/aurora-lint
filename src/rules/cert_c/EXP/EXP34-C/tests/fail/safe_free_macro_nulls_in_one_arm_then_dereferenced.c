/*
 * Rule: EXP34-C
 * Source: custom
 * Status: FAIL - Should trigger EXP34-C violation
 * Description: SAFE_FREE nulls its argument when TRACK is defined, so in
 * that build `return *p` dereferences a null pointer. The other build's
 * definition only frees, but a null that one live definition produces is
 * enough to start the finding.
 */

#include <stdlib.h>

#ifdef TRACK
#define SAFE_FREE(x) do { free(x); (x) = NULL; } while (0)
#else
#define SAFE_FREE(x) free(x)
#endif

int f(int *p)
{
    SAFE_FREE(p);
    return *p;
}
