#include <assert.h>

static int counter;

static int bump(void)
{
    return ++counter;
}

/* The builds that call check() never include the project's header. */
#ifdef USE_MYASSERT
#include "myassert.h"
#else
void check(void)
{
    assert(bump());
}
#endif
