#ifdef CONFIG_FEATURE

#include <assert.h>
#include "myassert.h"

static int counter;

static int bump(void)
{
    return ++counter;
}

void check(void)
{
    assert(bump());
}

#endif
