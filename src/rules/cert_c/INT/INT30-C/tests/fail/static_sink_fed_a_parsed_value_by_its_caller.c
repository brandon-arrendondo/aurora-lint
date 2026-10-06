/*
 * Rule: INT30-C
 * Source: regression
 * Status: FAIL - the static sink's only caller passes strtoul's result
 *
 * Written inline in the caller, `strtoul(s, NULL, 10) + 1u` can wrap and is
 * reported. Handed through a parameter it is the same value, so the
 * parameter is judged by what its caller passes, not by whether the
 * caller's body calls a listed input function.
 */
#include <stdlib.h>

static unsigned int sink(unsigned int data)
{
    return data + 1u;
}

unsigned int caller(const char *s)
{
    unsigned int data = (unsigned int)strtoul(s, NULL, 10);
    return sink(data);
}
