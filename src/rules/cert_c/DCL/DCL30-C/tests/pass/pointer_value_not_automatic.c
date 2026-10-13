/*
 * Rule: DCL30-C
 * Status: PASS - Should NOT trigger DCL30-C violation
 * Reason: A local pointer is judged by what it holds, never by being a
 *         local. Each one here holds heap memory, static storage, the
 *         caller's own pointer, or a value the body does not decide on
 *         every path, so no automatic object's address escapes.
 */

#include <stdlib.h>
#include <string.h>

char *heap_via_local(size_t n)
{
    char *p = malloc(n);
    return p;
}

char *static_via_local(void)
{
    static char s[16];
    char *p = s;
    return p;
}

char *callers_pointer(char *in)
{
    char *p = in;
    return p;
}

char *found_in_callers_string(const char *s)
{
    char *p = strchr(s, ':');
    return p;
}

char *set_in_a_branch(int c)
{
    char buf[8];
    char *p = NULL;
    if (c)
        p = buf;
    return p;
}

char *array_parameter(char a[16])
{
    return a;
}
