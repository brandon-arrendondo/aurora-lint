/*
 * Rule: FIO42-C
 *
 * Status: FAIL - Should trigger FIO42-C violation
 *
 * fgets() and fprintf() use the stream and give it back; neither closes or
 * keeps it, so the stream is still open when the function returns.
 */
#include <stdio.h>

int copy_first_line(const char *path, FILE *out)
{
    char line[256];
    FILE *in = fopen(path, "r");
    if (in == NULL)
        return -1;
    if (fgets(line, sizeof line, in) != NULL)
        fprintf(out, "%s", line);
    return 0;
}
