#include "internal.h"

void check(char *p, char *start, int n)
{
    assert( (wide64)(p - start)==n );
}
