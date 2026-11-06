/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: PASS - Only a library call runs between the assignment and the shift
 *
 * `gs` is assigned 3 and its address is never taken. `strlen` cannot
 * write it, so the shift is by 3.
 */

#include <string.h>

int gs;

int mask(const char *p)
{
    gs = 3;
    size_t n = strlen(p);
    return (1 << gs) + (int)n;
}
