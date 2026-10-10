/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - Every guard's branch always leaves
 *
 * Each zero branch ends in a statement control cannot fall out of: a
 * return, a call to exit(), a break out of the loop holding the division, or
 * an if/else whose arms both return.
 */
#include <stdio.h>
#include <stdlib.h>

int plain_return(int a, int b)
{
    if (b == 0)
        return 0;
    return a / b;
}

int logs_then_exits(int a, int b)
{
    if (b == 0) {
        fputs("zero divisor\n", stderr);
        exit(1);
    }
    return a / b;
}

int both_arms_return(int a, int b, int v)
{
    if (b == 0) {
        if (v)
            return -1;
        else
            return 0;
    }
    return a / b;
}

int sum_until_zero(const int *d, int n, int a)
{
    int total = 0;
    for (int i = 0; i < n; i++) {
        if (d[i] == 0) {
            break;
        }
        total += a / d[i];
    }
    return total;
}
