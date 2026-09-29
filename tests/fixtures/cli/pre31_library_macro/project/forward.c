#include "fwd.h"

int lower_next(const char **p)
{
    return LOWER(*(*p)++);
}

int read_next(FILE **files)
{
    return READ(*files++);
}
