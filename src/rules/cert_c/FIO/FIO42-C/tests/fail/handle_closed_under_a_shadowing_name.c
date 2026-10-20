/*
 * Rule: FIO42-C
 *
 * Status: FAIL - Should trigger FIO42-C violation
 *
 * The fclose() in the inner block closes the inner f, a different object
 * from the stream opened in the outer one, which is never closed.
 */
#include <stdio.h>

int count_lines(const char *path)
{
    FILE *f = fopen(path, "r");
    int lines = 0;
    if (f == NULL)
        return -1;
    while (fgetc(f) != EOF)
        lines++;
    {
        FILE *f = fopen("/dev/null", "w");
        if (f != NULL)
            fclose(f);
    }
    return lines;
}
