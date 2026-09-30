/*
 * Rule: FIO30-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO30-C violation
 */

/*
 * Rule: FIO30-C - Exclude user input from format strings
 * Status: FAIL
 * Reason: A cast does not change where its value came from: user input cast
 *         to a const pointer is still user input in the format slot.
 */

#include <stdio.h>

int main(int argc, char *argv[])
{
    // VULNERABLE: user input, cast, used as the format string
    printf((const char *)argv[1]);
    return 0;
}
