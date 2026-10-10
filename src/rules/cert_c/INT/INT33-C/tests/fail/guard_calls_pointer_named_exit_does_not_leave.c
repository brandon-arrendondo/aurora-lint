/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The zero branch calls a local function pointer named exit
 *
 * The block-scope `exit` is a pointer to log_zero(), which returns, so the
 * call is not the standard library's exit() and the division still runs
 * when b is zero (ADR-0006).
 */
#include <stdlib.h>

void log_zero(int code);

int divide(int a, int b)
{
    void (*exit)(int) = log_zero;
    if (b == 0) {
        exit(1);
    }
    return a / b;
}
