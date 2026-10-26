#include "myassert.h"
#include <assert.h>

static int counter;

static int bump(void)
{
    return ++counter;
}

/* <assert.h> defines assert anew: NDEBUG drops the call. */
void check(void)
{
    assert(bump());
}
