#include "conf.h"

static int counter;

static int next(void)
{
    return ++counter;
}

int k(void)
{
    return conv(next());
}
