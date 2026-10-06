/*
 * Rule: INT32-C
 * Source: regression
 * Status: FAIL - a relay forwards its caller's full-range value to the sink
 *
 * relay() passes its own parameter on, so the sink's parameter is judged by
 * what relay's caller passes: the result of rand().
 */
#include <stdlib.h>

static int sink(int data)
{
    return data + 1;
}

static int relay(int data)
{
    return sink(data);
}

int caller(void)
{
    return relay(rand());
}
