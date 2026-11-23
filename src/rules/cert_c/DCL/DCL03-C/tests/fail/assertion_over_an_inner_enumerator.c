/*
 * Rule: DCL03-C
 * Source: synthetic
 * Status: FAIL - An assertion over an enumerator that hides an object
 * Expect: count=2
 *
 * Inside the block, `slots` and `limit` are enumerators, though a
 * parameter and a file-scope object of those names enclose them, so each
 * condition is an integer constant expression that a static assertion
 * could test (C11 6.7.10).
 */
#include <assert.h>

int limit;

void check(int slots)
{
    {
        enum { slots = 8, limit = 64 };
        assert(slots == 8);
        assert(slots * 8 <= limit);
    }
}
