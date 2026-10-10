/*
 * Rule: MSC07-C
 * Source: synthetic
 * Status: PASS - The statement after a call to the file's own exit() runs
 *
 * This file defines its own static exit(), which returns. The statement
 * after the call is reachable, so reporting it as unreachable "after a
 * noreturn function call" would name a call that is not there (ADR-0005,
 * ADR-0006).
 */
#include <stdio.h>

static int counter;

static void exit(int c)
{
    counter += c;
}

void finish(void)
{
    exit(1);
    printf("still running\n");
}
