/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - in `((p = get()) && (p = other(), 1)) && *p`, the left operand ends by storing a new value in `p`, so its test no longer covers `*p`
 */

#include <stddef.h>

char *get(void);
char *other(void);
void note_missing(void);

int f(void)
{
    char *p;
    return ((p = get()) && (p = other(), 1)) && *p;
}
