/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - The static is declared in the arm the function is not in
 *
 * The function is in the #else arm, which never compiles with the #if arm's
 * static. Its `total` comes from a header this file does not show.
 */

#include "other.h"

#ifdef LOCAL_TOTAL
static long total;
#else
void add(long n)
{
    total += n;
}
#endif
