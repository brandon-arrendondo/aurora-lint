/*
 * Rule: INT32-C
 * Source: regression
 * Status: FAIL - the parameter used in the addition receives console input
 *
 * The caller passes fscanf's result at position 0 and a constant at
 * position 1. The addition reads position 0, so it is reported.
 */
#include <stdio.h>

static int sink(int input, int step)
{
    (void)step;
    return input + 1;
}

int caller(void)
{
    int input = 0;
    if (fscanf(stdin, "%d", &input) != 1)
        return 0;
    return sink(input, 5);
}
