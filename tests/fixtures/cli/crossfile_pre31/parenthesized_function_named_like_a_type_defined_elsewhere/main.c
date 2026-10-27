#include "steps.h"

#define TWICE(x) ((x) + (x))

int twice_stepped(void)
{
    return TWICE((step_t)(1));
}
