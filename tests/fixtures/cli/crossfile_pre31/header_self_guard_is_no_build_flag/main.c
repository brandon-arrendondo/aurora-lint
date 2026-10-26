#include "twice.h"

int sum(int i)
{
#if defined(TWICE)
    return TWICE(i++);
#else
    return i;
#endif
}
