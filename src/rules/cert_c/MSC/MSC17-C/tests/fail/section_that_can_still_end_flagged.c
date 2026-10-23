/*
 * Rule: MSC17-C
 * Source: synthetic
 * Status: FAIL - Should trigger MSC17-C violation
 * Expect: default=violation strict=violation pedantic=violation
 *
 * Near misses of a section that never ends, each of which can still fall
 * through to the next label: exit() on only one arm of an if, an endless
 * loop that a break can leave, and a call to a function nothing declares
 * noreturn.
 */
#include <stdlib.h>

void work(int step);
void finish(void);

void dispatch(int op)
{
    switch (op) {
    case 1:
        if (op > 0)
            exit(1);
    case 2:
        for (;;) {
            if (op)
                break;
        }
    case 3:
        work(3);
        finish();
    default:
        work(0);
        break;
    }
}
