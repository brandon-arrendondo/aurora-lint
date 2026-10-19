/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - the comma's value is get(2), not s, so the test proves nothing about s
 */

#include <stdlib.h>

char *get(int);

int comma(void)
{
    char *s;
    if ((s = get(1), get(2)) == NULL || *s == 0)
        return 1;
    return 0;
}
