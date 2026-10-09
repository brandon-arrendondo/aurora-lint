/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - The zero branch calls the project's own noreturn function
 *
 * fatal() calls exit() unconditionally, so it never returns and the branch
 * leaves. The credit comes from the shared noreturn set, not from the
 * callee's name.
 */
#include <stdio.h>
#include <stdlib.h>

static void fatal(const char *msg)
{
    fputs(msg, stderr);
    exit(1);
}

int divide(int a, int b)
{
    if (b == 0) {
        fatal("zero divisor\n");
    }
    return a / b;
}
