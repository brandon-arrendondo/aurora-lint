/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: PASS - another translation unit may call a function with external linkage
 */
#include <stdio.h>

void exported(void)
{
    puts("done");
}
