/*
 * Rule: DCL30-C
 * Source: synthetic
 * Status: PASS - The file-scope object is declared in the arm the function is not in
 *
 * The function is in the #else arm, so the #if arm's file-scope `slot` is
 * not the one it writes, and nothing here says what is.
 */

#include "other.h"

#ifdef WITH_SLOT
char *slot;
#else
void configure(void)
{
    char buf[8];

    slot = buf;
    use(slot);
}
#endif
