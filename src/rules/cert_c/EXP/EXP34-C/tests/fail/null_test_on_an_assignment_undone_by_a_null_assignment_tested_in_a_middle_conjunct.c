/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - in `(p = get()) && (p = 0) == 0 && *p`, `(p = 0) == 0` stores NULL in `p` and holds, so `*p` reads a null pointer
 */

#include <stddef.h>

char *get(void);
char *other(void);
void note_missing(void);

int f(void)
{
    char *p;
    return (p = get()) && (p = 0) == 0 && *p;
}
