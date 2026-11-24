/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: FAIL - a local passed to a library call pastes nothing, whatever the static's name ends with
 */
#include <stdio.h>

static const char *get_name(void) /* Expect: here */
{
    return "x";
}

int api(char *buf, int n)
{
    const char *name = "y";
    return snprintf(buf, n, "%s", name);
}
