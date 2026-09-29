#include "../common/twice.h"
#include "once.h"

int side_cubed(int *s)
{
    return CUBE((*s)++);
}
