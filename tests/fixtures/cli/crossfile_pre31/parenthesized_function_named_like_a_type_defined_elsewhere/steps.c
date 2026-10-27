#include "steps.h"

static int position;

int step_t(int n)
{
    position += n;
    return position;
}
