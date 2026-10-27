#include "handlers.h"

#define TWICE(x) ((x) + (x))

int twice_handled(void)
{
    return TWICE((handler_t)(1));
}
