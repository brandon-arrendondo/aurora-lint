/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - A guard bounds only the object it reads, as it is when the conversion runs
 * Expect: count=2
 *
 * The inner `x` hides the guarded one, so the guard says nothing about the
 * value converted. In the loop, the write after the cast reaches it on the
 * next iteration, so the guard no longer bounds `x` there.
 */

#include <limits.h>

int get(void);
void sink(int);

void hidden(int x)
{
    signed char c = 0;
    if (x <= SCHAR_MAX && x >= SCHAR_MIN) {
        {
            int x = get();
            c = (signed char)x; /* Expect: here */
        }
    }
    sink(c);
}

void rewritten_in_loop(int x)
{
    signed char c = 0;
    if (x <= SCHAR_MAX && x >= SCHAR_MIN) {
        while (get()) {
            c = (signed char)x; /* Expect: here */
            x += 1000;
        }
    }
    sink(c);
}
