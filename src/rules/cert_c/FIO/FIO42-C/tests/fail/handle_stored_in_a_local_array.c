/*
 * Rule: FIO42-C
 *
 * Status: FAIL - Should trigger FIO42-C violation
 *
 * The stream is copied into an array that is local to the function and is
 * gone when it returns; nothing closes either copy.
 */
#include <stdio.h>

void stage(const char *path)
{
    FILE *streams[2];
    FILE *f = fopen(path, "r");
    streams[0] = f;
}
