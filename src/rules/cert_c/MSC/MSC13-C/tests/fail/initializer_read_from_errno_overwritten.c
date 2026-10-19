/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: FAIL - `errno` and `stdout` are the library's objects, whatever a header spells them as, so their value is the program's state and no default
 */

#include <errno.h>
#include <stdio.h>

int get(void);

int saved_error(void)
{
    int e = errno;
    e = get();
    return e;
}

FILE *stream(int k)
{
    FILE *f = stdout;
    f = k ? stderr : stdin;
    return f;
}
