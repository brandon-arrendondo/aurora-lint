/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP33-C violation. `if (flag) memset(out, ...)`
 * is a MAY-write, so the caller can still read its variable uninitialized. The
 * library-call write credit added in task 1026 therefore routes through the
 * same MUST/MAY refinement an assignment does; crediting it outright -- or
 * leaving it invisible, which promotes it for having been unseen -- would
 * silence this.
 */
#include <stdio.h>
#include <string.h>

struct out {
    int a;
};

static void maybe_clear(int flag, struct out *o)
{
    if (flag)
        memset(o, 0, sizeof(*o));
}

void caller(int flag)
{
    struct out o;

    maybe_clear(flag, &o);
    printf("%d\n", o.a);
}
