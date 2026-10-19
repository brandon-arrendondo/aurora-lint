/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - in `(p = get()) ? ((p = other()) ? 0 : *p) : 0`, the inner condition tests the new value of `p`, and its alternative runs when that value is NULL
 */

#include <stddef.h>

char *get(void);
char *other(void);
void note_missing(void);

int f(void)
{
    char *p;
    return (p = get()) ? ((p = other()) ? 0 : *p) : 0;
}
