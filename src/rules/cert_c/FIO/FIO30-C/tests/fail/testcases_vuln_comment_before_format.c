/*
 * Rule: FIO30-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO30-C violation
 */

/*
 * Rule: FIO30-C - Exclude user input from format strings
 * Status: FAIL
 * Reason: Skipping a comment between arguments must still find the real
 *         format argument after it, and here that argument is user input.
 */

#include <stdio.h>

int main(int argc, char *argv[])
{
    char buf[64];

    // VULNERABLE: the format after the comment is user input
    snprintf(buf, sizeof(buf), /* caller-supplied */ argv[1]);
    puts(buf);
    return 0;
}
