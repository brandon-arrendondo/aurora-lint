/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - in `(p = get()) && (RESET(), 1) && *p`, the macro `RESET()` is handed nothing but its body stores NULL in `p`, so `*p` reads a null pointer
 */

#include <stddef.h>

#define RESET() (p = NULL)

char *get(void);

int f(void)
{
    char *p;
    return (p = get()) && (RESET(), 1) && *p;
}
