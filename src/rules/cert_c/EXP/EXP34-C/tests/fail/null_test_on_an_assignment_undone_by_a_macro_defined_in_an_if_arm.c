/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - the #if 1 arm defines `RESET()` to store NULL in `p`, so `*p` reads a null pointer, whatever the #else arm defines
 */

#include <stddef.h>

#if 1
#define RESET() (p = NULL)
#else
#define RESET() 0
#endif

char *get(void);

int f(void)
{
    char *p;
    return (p = get()) && (RESET(), 1) && *p;
}
