/*
 * Rule: INT08-C
 * Source: synthetic
 * Status: PASS - the guard rules out the value the square would overflow
 *
 * `data` is 32767, and `llabs(data) <= 181` is false for it, so the
 * guarded square never runs with that value: the branch is unreachable.
 */
#include <stdlib.h>

void printIntLine(int);

void guarded(void)
{
    short data = 32767;
    if (llabs((long long)data) <= 181)
    {
        short result = data * data;
        printIntLine(result);
    }
}
