#include "sq.h"

int alt(int);

/* Only an ALT build replaces SQ; the call compiles only without it, where
 * the header's SQ evaluates its argument twice. */
#ifdef ALT
#undef SQ
#define SQ(x) alt(x)
#endif

int area(int i)
{
#ifndef ALT
    return SQ(i++);
#else
    return 0;
#endif
}
