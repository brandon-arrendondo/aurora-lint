/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - in `(p = get()) && (p = other(), *p)`, the comma in the guarded operand stores a new value in `p` before reading `*p`
 */

#include <stddef.h>

char *get(void);
char *other(void);
void note_missing(void);

int f(void)
{
    char *p;
    return (p = get()) && (p = other(), *p);
}
