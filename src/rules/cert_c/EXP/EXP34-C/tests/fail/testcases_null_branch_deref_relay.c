/*
 * Rule: EXP34-C
 * Source: testcases (hostap caller-contract cohort)
 * Status: FAIL - the relay sits in the TRUE branch of `!data`, where the
 *         pointer IS null. Companion to
 *         pass/testcases_short_circuit_caller_guard.c: crediting the mere
 *         presence of a dominating null test, rather than the branch it
 *         selects, would invert this answer and mask the defect.
 */

#include <stdio.h>

static int sink(const int *ptr)
{
    return *ptr;
}

int relay(void)
{
    int *data = NULL;

    if (!data)
        return sink(data);

    return 0;
}
