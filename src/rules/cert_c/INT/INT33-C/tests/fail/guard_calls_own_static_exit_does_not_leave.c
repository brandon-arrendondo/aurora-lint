/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The zero branch calls the file's own exit(), which returns
 *
 * This file defines its own static exit(), which only counts. A call to it
 * reaches that body, not the standard library's exit(), so the branch
 * falls through to the division when b is zero. A library name is noreturn
 * only when the call names the library's function (ADR-0006).
 */

static int counter;

static void exit(int c)
{
    counter += c;
}

int divide(int a, int b)
{
    if (b == 0) {
        exit(1);
    }
    return a / b;
}
