#include "twice.h"
#include "fast.h"

/* FAST is defined after twice.h made TWICE, so TWICE stands here. */
int sum(int i)
{
#ifdef FAST
    return TWICE(i++);
#else
    return i;
#endif
}
