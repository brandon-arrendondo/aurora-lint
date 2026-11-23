/*
 * Rule: DCL03-C
 * Source: synthetic
 * Status: PASS - An assertion over an object that hides an enumerator
 *
 * Inside the block, `slots` is an object, though an enumerator of the
 * same name encloses it, so the condition reads an object at run time
 * and no static assertion can test it.
 */
#include <assert.h>

enum { slots = 8 };

void check(int count)
{
    {
        int slots = count;
        assert(slots == 8);
    }
}
