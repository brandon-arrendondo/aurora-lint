/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - An array this file does not declare has no size here
 *
 * `buf` at the access comes from the header. The local array of the same
 * name is declared in a later block, and says nothing about it.
 */

#include "other.h"

int element(void)
{
    int r = buf[7];
    {
        int buf[4];
        buf[0] = 1;
        r += buf[0];
    }
    return r;
}
