/*
 * Rule: INT32-C
 * Source: synthetic
 * Status: PASS - INT_MIN is ruled out before abs is taken
 * Settings: data_model=lp64
 *
 * With `data > INT_MIN` tested first, every value abs is given has an
 * absolute value, so `abs(data) <= 46340` bounds `data` to -46340..46340
 * and the product, at most 2147395600, fits in an int.
 */
#include <limits.h>
#include <stdlib.h>

void printIntLine(int);

void guarded(int data)
{
    if (data > INT_MIN && abs(data) <= 46340)
    {
        int result = data * data;
        printIntLine(result);
    }
}
