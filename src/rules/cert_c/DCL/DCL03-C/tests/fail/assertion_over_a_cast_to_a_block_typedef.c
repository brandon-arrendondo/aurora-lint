/*
 * Rule: DCL03-C
 * Source: synthetic
 * Status: FAIL - an assertion over a cast to a block typedef
 * Expect: count=1
 *
 * Inside the function, `len` is the typedef that hides the file-scope
 * object of that name, so `(len)4 == 4` is an integer constant expression
 * a static assertion could test.
 */
#include <assert.h>

int len = 4;

void check(void)
{
    typedef unsigned len;
    assert((len)4 == 4);
}
