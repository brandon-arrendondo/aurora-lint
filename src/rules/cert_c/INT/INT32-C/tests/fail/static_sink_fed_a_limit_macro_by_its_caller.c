/*
 * Rule: INT32-C
 * Source: regression
 * Status: FAIL - the static sink's only caller passes INT_MAX
 * Settings: data_model=lp64
 *
 * Under a declared data model INT_MAX is a number, so the constant the one
 * caller passes reaches the sink's parameter and `data + 1` provably
 * overflows, as it is reported when written inline in the caller.
 */
#include <limits.h>

static int sink(int data)
{
    return data + 1;
}

int caller(void)
{
    int data = 0;
    data = INT_MAX;
    return sink(data);
}
