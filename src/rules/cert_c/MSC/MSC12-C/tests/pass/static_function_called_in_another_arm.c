/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: PASS - a call in an arm some configuration compiles keeps the static live
 */
#include <stdio.h>

static void win_only(void)
{
    puts("done");
}

void api(void)
{
#ifdef _WIN32
    win_only();
#endif
}
