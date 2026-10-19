/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - `SAVE()` stores the address of `p` where `reset()` may store NULL through it, so `*p` may read a null pointer
 */

#include <stddef.h>

char **saved;
char *get(void);
void reset(void);

#define SAVE() (saved = &p)

int f(void)
{
    char *p;
    SAVE();
    return (p = get()) && (reset(), 1) && *p;
}
