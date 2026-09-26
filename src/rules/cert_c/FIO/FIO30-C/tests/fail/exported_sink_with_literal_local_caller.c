/*
 * Rule: FIO30-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO30-C violation
 */

/*
 * Rule: FIO30-C - Exclude user input from format strings
 * Status: FAIL
 * Reason: The one caller in this file passes a literal, but show() has
 * external linkage, so callers in other translation units can pass anything.
 * The literal the visible caller passes is not a proof about the parameter.
 */

#include <stdio.h>

void show(const char *fmt)
{
    printf(fmt);
}

void banner(void)
{
    show("ready\n");
}
