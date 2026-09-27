#include "counters.h"

int next_id(int n)
{
    DBG_COUNT(n++);
    return n;
}
