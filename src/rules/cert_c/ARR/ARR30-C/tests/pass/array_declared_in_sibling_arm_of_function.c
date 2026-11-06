/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The array is declared in the arm the function is not in
 *
 * The four-element `buf` is declared in the #if arm and the function in
 * the #else arm, so the function's `buf` comes from the header, whose
 * size is not this arm's.
 */

#include "other.h"

#if defined(B)
char buf[4];
#else
int element(void)
{
#if defined(A)
    int i = 7;
#else
    int i = 3;
#endif
    return buf[i];
}
#endif
