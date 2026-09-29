#define WHICH_DEFS "config_defs.h"
#include WHICH_DEFS
#include "shapes.h"

int side_squared(int *s)
{
    return SQ((*s)++);
}
