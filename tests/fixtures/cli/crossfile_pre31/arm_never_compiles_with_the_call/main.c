#include "opt.h"

int scan(int i)
{
#ifndef OMIT_GET
    get_opt(i++);
#endif
    return i;
}
