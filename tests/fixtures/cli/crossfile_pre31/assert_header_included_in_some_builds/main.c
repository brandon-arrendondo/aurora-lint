#include <assert.h>
#ifdef USE_MYASSERT
#include "myassert.h"
#endif

static int counter;

static int bump(void)
{
    return ++counter;
}

void check(void)
{
    assert(bump());
}
