/*
 * Rule: FIO42-C
 *
 * Status: FAIL - Should trigger FIO42-C violation
 *
 * The store through slot lands in the local f, not in the caller's storage,
 * so the stream is still this function's to close, and it never is.
 */
#include <stdio.h>

void stage(const char *path)
{
    FILE *f = NULL;
    FILE **slot = &f;
    {
        FILE *opened = fopen(path, "r");
        *slot = opened;
    }
    if (*slot != NULL)
        fputc('x', *slot);
}
