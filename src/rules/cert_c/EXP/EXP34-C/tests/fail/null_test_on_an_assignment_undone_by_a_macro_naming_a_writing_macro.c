/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - `CLEAR` expands to the name `RESET`, which the call's parentheses then invoke, and `RESET()` stores NULL in `p`, so `*p` reads a null pointer
 */

#include <stddef.h>

#define RESET() (p = NULL)
#define CLEAR RESET

char *get(void);

int f(void)
{
    char *p;
    return (p = get()) && (CLEAR(), 1) && *p;
}
