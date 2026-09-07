/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP33-C violation. A forward only covers the
 * output when the callee it forwards to is itself a MUST-write. Here the
 * forwarded-to function writes under a condition, so the obligation the
 * coverage walk parks is never discharged -- and an undischarged obligation
 * must leave the summary exactly as it found it, or the parameter drops out of
 * the read-only-dereference set and the conservative `&var` fallback credits
 * it anyway. The boundary of the credit added in task 1027.
 */
#include <stdio.h>

static void maybe_fill(unsigned char *out, int flag)
{
    if (flag)
        out[0] = 0;
}

static void randit(unsigned int *rnd, int flag)
{
    maybe_fill((unsigned char *)rnd, flag);
}

void caller(int flag)
{
    unsigned int r;

    randit(&r, flag);
    printf("%u\n", r);
}
