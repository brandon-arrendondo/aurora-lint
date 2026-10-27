#include <assert.h>

static int counter;

static int bump(void)
{
    return ++counter;
}

/* The include and the call compile in the same builds. */
#ifdef USE_MYASSERT
#include "myassert.h"

void check(void)
{
    assert(bump());
}
#endif
