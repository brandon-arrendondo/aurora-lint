/*
 * Rule: INT32-C
 * Source: regression
 * Status: FAIL - the static sink's only caller passes a full-range value
 *
 * The addition sits in a static function whose one caller passes the result
 * of rand(). Written inline in the caller, `rand() + 1` is reported; handed
 * through a parameter it is the same value, so the parameter is judged by
 * what its caller passes, not by whether the caller reads external input.
 */
#include <stdlib.h>

static int sink(int data)
{
    return data + 1;
}

int caller(void)
{
    int data = rand();
    return sink(data);
}
