/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: FAIL - the static is uncalled in every configuration that compiles it (the Juliet shape)
 */
#include <stdio.h>

#ifndef OMITBAD
/* The comment names helperBad, and so does the string: neither calls it. */
static void helperBad() /* Expect: here */
{
    puts("helperBad()");
}

void entry_bad()
{
    puts("entry_bad()");
}
#endif

#ifndef OMITGOOD
static void helperGood()
{
    puts("helperGood()");
}

void entry_good()
{
    helperGood();
}
#endif
