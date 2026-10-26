#include "log.h"

int f(int x)
{
    if (x)
        return 1;
    FATAL("x");
}
