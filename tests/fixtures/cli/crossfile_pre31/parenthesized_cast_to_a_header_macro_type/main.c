#include "types.h"

#define TWICE(x) ((x) + (x))

u32 sum(u32 a, u32 b)
{
    return TWICE((u32) (a + b));
}
