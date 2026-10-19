/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - in `p && (p = other(), *p)`, the comma in the guarded operand stores a new value in `p` before reading `*p`
 */

#include <stddef.h>

char *get(void);
char *other(void);
void note_missing(void);

int f(char *p)
{
    if (p == NULL)
        note_missing();
    return p && (p = other(), *p);
}
