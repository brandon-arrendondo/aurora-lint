/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - the GCC nested function `clear` stores NULL in `p`, so the call between the test and `*p` may leave it NULL
 */

#include <stddef.h>

char *get(void);

int f(void)
{
    char *p;
    void clear(void)
    {
        p = NULL;
    }
    return (p = get()) && (clear(), 1) && *p;
}
