#include "opt.h"

/* The call compiles in every build, the OMIT_GET one included. */
int scan(int i)
{
    get_opt(i++);
    return i;
}
