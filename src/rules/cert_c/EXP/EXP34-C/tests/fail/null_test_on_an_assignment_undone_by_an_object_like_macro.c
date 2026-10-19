/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - in `(p = get()) && (CLR, 1) && *p`, the object-like macro `CLR` expands to `p = NULL`, so `*p` reads a null pointer
 */

#include <stddef.h>

#define CLR p = NULL

char *get(void);

int f(void)
{
    char *p;
    return (p = get()) && (CLR, 1) && *p;
}
