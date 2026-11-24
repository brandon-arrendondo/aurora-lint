/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: PASS - a macro builds the function's name, so no function of the macro's name is defined
 */
#include <stdio.h>

#define NS(n) lib_##n

static int NS(alpha)(int x)
{
    return x + 1;
}

static int NS(beta)(int x)
{
    return x + 2;
}

int api(int x)
{
    return NS(alpha)(x) + NS(beta)(x);
}
