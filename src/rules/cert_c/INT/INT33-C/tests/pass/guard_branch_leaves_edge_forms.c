/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - Each zero branch never falls through, in a less common form
 *
 * A stray empty statement after exit(), a loop that never ends, and a call
 * to exit() through a dereference all keep control from reaching the
 * division when the divisor is zero.
 */
#include <stdlib.h>

int trailing_empty_statement(int a, int b)
{
    if (b == 0) {
        exit(1);
        ;
    }
    return a / b;
}

int loop_without_break(int a, int b, int ready)
{
    if (b == 0) {
        for (;;) {
            if (ready)
                return 0;
        }
    }
    return a / b;
}

int dereferenced_exit(int a, int b)
{
    if (b == 0) {
        (*exit)(1);
    }
    return a / b;
}
