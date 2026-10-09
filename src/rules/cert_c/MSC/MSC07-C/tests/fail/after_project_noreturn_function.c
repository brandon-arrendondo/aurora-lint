/*
 * Rule: MSC07-C
 * Source: synthetic
 * Status: FAIL - Code after a call to the project's own noreturn function
 *
 * die() calls exit() unconditionally, so it never returns and the printf
 * after the call cannot run. Recognized from the shared noreturn set, not
 * from a list of library names.
 */
#include <stdio.h>
#include <stdlib.h>

static void die(const char *msg)
{
    fputs(msg, stderr);
    exit(1);
}

void load(const char *path)
{
    if (path == NULL) {
        die("no path\n");
        printf("unreachable\n");
    }
}
