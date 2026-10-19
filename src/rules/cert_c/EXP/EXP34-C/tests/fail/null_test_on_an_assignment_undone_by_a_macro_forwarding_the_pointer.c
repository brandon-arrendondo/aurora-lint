/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - `RESET(p)` hands `p` to `SETNULL`, which stores NULL in it, so `*p` reads a null pointer
 */

#include <stddef.h>

#define SETNULL(v) ((v) = NULL)
#define RESET(v) SETNULL(v)

char *get(void);

int f(void)
{
    char *p;
    return (p = get()) && (RESET(p), 1) && *p;
}
