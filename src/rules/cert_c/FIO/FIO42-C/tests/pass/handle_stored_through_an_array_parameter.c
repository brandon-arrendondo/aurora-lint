/*
 * Rule: FIO42-C
 *
 * Status: PASS - Should NOT trigger FIO42-C violation
 *
 * A parameter written with array syntax is a pointer: the element it stores
 * the stream in is the caller's.
 */
#include <stdio.h>

int open_into(FILE *out[], const char *path)
{
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    out[0] = f;
    return 0;
}
