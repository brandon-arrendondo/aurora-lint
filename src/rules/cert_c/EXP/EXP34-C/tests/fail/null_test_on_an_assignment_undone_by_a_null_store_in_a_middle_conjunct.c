/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - in `(p = get()) != 0 && (p = 0, 1) && *p`, a middle conjunct stores NULL in `p`, so `*p` reads a null pointer
 */

#include <stddef.h>

char *get(void);
char *other(void);
void note_missing(void);

int f(void)
{
    char *p;
    return (p = get()) != 0 && (p = 0, 1) && *p;
}
