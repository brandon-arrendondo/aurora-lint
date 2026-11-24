/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: PASS - a file of statics only is a piece another file includes
 *
 * A generated bundle `#include`s this file and calls test_entry through a
 * table; the file has no function of its own that another file could call.
 */
#include <stdio.h>

static int helper(int v)
{
    return v * 2;
}

static int test_entry(const char *arg)
{
    puts(arg);
    return helper(1);
}
