/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to the same array
 * Status: FAIL
 * Reason: `cursor` walks `head` where the subtraction is written and only
 *         switches to `tail` below it, so `cursor - tail` really does span
 *         two distinct arrays. This is the reporting direction of the same
 *         defect the pass case covers: with one base per name the last
 *         assignment wins everywhere, the line below reads as `tail - tail`,
 *         and a genuine violation goes unreported.
 */

#include <stdio.h>

long distance_before_switch(void)
{
    char head[16];
    char tail[16];
    char *cursor = head;
    long gap;

    gap = cursor - tail; /* head vs tail: undefined */

    cursor = tail;
    while (cursor < tail + sizeof(tail)) {
        *cursor++ = 0;
    }

    return gap;
}

int main(void)
{
    printf("%ld\n", distance_before_switch());
    return 0;
}
