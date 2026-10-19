/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - the right operand of `(s = e) == NULL && *s` runs only when s is NULL
 */

#include <stdlib.h>

char *get(int);

int wrong_side(void)
{
    char *s;
    if ((s = get(1)) == NULL && *s == 0)
        return 1;
    return 0;
}
