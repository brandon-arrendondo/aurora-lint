/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - `p` is static, so the call `h()` that the macro `CALLH()` expands to may store NULL in it after the test, and `*p` may read a null pointer
 */

#include <stddef.h>

#define CALLH() h()

char *get(void);
void h(void);

int f(void)
{
    static char *p;
    return (p = get()) && (CALLH(), 1) && *p;
}
