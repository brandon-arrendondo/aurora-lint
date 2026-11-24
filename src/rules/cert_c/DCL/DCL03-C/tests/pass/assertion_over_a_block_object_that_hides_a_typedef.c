/*
 * Rule: DCL03-C
 * Source: synthetic
 * Status: PASS - an assertion over a block object that hides a typedef
 *
 * Inside the function, `count` is the object, so `(count) + 1 == 2` reads
 * it at run time and no static assertion can test it.
 */
#include <assert.h>

typedef unsigned count;

void check(int n)
{
    int count = n;
    assert((count) + 1 == 2);
}
