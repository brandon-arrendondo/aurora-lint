#include "math_util.h"

int sum_squares(const int *v, int n)
{
    int i = 0, total = 0;
    while (i < n)
        total += SQ(v[i++]);
    return total;
}
