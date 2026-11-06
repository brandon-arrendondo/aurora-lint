/*
 * Rule: INT30-C
 * Source: synthetic
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * `KC` is a const object of the include guard the functions are in, so each
 * size is a product of constants, read as it is with no guard around the
 * file: the default preset takes a constant product as the programmer's
 * own, and strict reports the product that wraps.
 */

#ifndef POOL_H
#define POOL_H

#include <stdlib.h>

static const unsigned long KC = 1000000000;

void *pool_huge(void)
{
    return malloc(KC * 1000000000);
}

void *pool_small(void)
{
    return malloc(KC * 4);
}

#endif
