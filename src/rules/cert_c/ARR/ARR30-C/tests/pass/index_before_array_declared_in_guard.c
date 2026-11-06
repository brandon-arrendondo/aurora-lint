/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The guard declares its array after the access
 *
 * `buf` comes from the header here; the guard's four-element `buf` is
 * declared after the function, so its size is not the one the access
 * indexes.
 */

#include "other.h"

#ifndef ELEMENT_H
#define ELEMENT_H

int element(void)
{
#if defined(A)
    int i = 7;
#else
    int i = 2;
#endif
    return buf[i];
}

char buf[4];

#endif
