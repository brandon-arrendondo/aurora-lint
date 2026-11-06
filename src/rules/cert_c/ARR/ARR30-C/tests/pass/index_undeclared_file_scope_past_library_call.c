/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Only a library call runs between the assignment and the access
 *
 * `gi` comes from an unread header and its address is never taken.
 * `strlen` cannot write it, so the access is at index 2.
 */

#include <string.h>
#include "other.h"

int buf[4];

int element(const char *p)
{
    gi = 2;
    size_t n = strlen(p);
    return buf[gi] + (int)n;
}
