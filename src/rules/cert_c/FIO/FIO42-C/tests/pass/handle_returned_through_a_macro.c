/*
 * Rule: FIO42-C
 *
 * Status: PASS - Should NOT trigger FIO42-C violation
 *
 * The macro expands to a return of its argument, so the stream goes to the
 * caller.
 */
#include <stdio.h>

#define RET(f) return (f)

FILE *open_log(const char *path)
{
    FILE *f = fopen(path, "a");
    RET(f);
}
