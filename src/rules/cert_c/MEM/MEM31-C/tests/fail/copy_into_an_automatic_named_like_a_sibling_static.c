/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: One block declares `static char *q`; a sibling block copies
 * its own allocation into an automatic `q` and drops `p`. The copy is
 * judged by the `q` it stores into, which is automatic, so the block leaks
 * at the return. The other block's `static q` does not hold it.
 * Expect: count=3
 */
#include <stdlib.h>
#include <string.h>

int keep(const char *x, int k)
{
    if (k) {
        static char *q;
        q = strdup(x);
        return 1;
    }
    {
        char *p = strdup(x); /* Expect: here */
        char *q;
        q = p;
        p = NULL;
        return 0; /* Expect: here */
    }
}
