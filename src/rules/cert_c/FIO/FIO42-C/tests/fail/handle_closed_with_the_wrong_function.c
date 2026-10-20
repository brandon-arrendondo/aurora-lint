/*
 * Rule: FIO42-C
 *
 * Status: FAIL - Should trigger FIO42-C violation
 *
 * A stream from fopen() is released only by fclose(); handing it, cast, to
 * close() leaves the FILE open, written directly or through a macro.
 */
#include <stdio.h>
#include <unistd.h>

#define DROP(f) close((int)(long)(f))

void stage(const char *path)
{
    FILE *f = fopen(path, "w+");
    if (f != NULL)
        close((int)(long)f);
}

void stage_through_a_macro(const char *path)
{
    FILE *f = fopen(path, "w+");
    if (f != NULL)
        DROP(f);
}
