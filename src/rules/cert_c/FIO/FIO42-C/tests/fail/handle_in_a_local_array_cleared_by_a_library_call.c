/*
 * Rule: FIO42-C
 *
 * Status: FAIL - Should trigger FIO42-C violation
 *
 * The array holding the stream is handed only to memset, which overwrites
 * the element and closes nothing.
 */
#include <stdio.h>
#include <string.h>

void reset(const char *path)
{
    FILE *fs[2];
    FILE *f = fopen(path, "r");
    fs[0] = f;
    memset(fs, 0, sizeof fs);
}
