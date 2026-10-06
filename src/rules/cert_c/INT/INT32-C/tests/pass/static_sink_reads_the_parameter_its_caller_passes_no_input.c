/*
 * Rule: INT32-C
 * Source: regression
 * Status: PASS - the parameter used in the addition receives no input
 *
 * The caller reads console input, but what it passes at position 1 is the
 * length of a local string, which no source reaches; the addition reads only
 * position 1. A parameter is judged by what its callers pass at its own
 * position, not by whether a caller reads input anywhere in its body.
 */
#include <stdio.h>
#include <string.h>

static int sink(int input, int step)
{
    (void)input;
    return step + 1;
}

int caller(void)
{
    char name[16] = "abc";
    int input = 0;
    if (fscanf(stdin, "%d", &input) != 1)
        return 0;
    return sink(input, (int)strlen(name));
}
