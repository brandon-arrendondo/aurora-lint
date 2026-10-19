/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - in `p != 0 && (p = 0, 1) && *p`, a middle conjunct stores NULL in `p`, so `*p` reads a null pointer
 */

#include <stddef.h>

char *get(void);
char *other(void);
void note_missing(void);

int f(char *p)
{
    if (p == NULL)
        note_missing();
    return p != 0 && (p = 0, 1) && *p;
}
