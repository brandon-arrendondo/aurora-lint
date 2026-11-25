#include "mod/module.h"

static void dev_register_types(void)
{
}

type_init(dev_register_types)

static int dev_unused_helper(int x)
{
    return x * 3;
}

int dev_api(int x)
{
    return x;
}
