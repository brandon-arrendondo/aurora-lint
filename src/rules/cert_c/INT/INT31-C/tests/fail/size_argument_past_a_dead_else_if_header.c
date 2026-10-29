/*
 * Rule: INT31-C
 * Source: custom
 * Status: FAIL - Should trigger INT31-C violation
 * Description: An #if 0 block that ends in `} else if (z)` holds a control
 * header no build has, so the brace block after its #endif is a plain
 * compound statement and the memcpy in it is live code. The block's last
 * line also closes the `{` its first line opened, so that `}` stays: without
 * it the live block would close the function, and the call would be lost.
 * Expect: count=1
 */

#include <string.h>

int copy_unless_reset(char *d, const char *s, int x, int z, int n)
{
#if 0
    if (x) {
        n = 0;
    } else if (z)
#endif
    {
        memcpy(d, s, n); /* Expect: here */
    }
    return n;
}
