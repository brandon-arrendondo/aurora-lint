/*
 * Rule: INT32-C
 * Source: synthetic
 * Status: FAIL - abs of a full-range int may be abs(INT_MIN)
 * Settings: data_model=lp64
 * Expect: count=1
 *
 * `data` may be INT_MIN, whose absolute value is not representable: abs
 * of it is undefined (C11 7.22.6.1p2), and an implementation that returns
 * INT_MIN passes `<= 46340`. So the guard does not bound `data`, and the
 * product may overflow.
 */
#include <stdlib.h>

void printIntLine(int);

void guarded_by_abs_alone(int data)
{
    if (abs(data) <= 46340)
    {
        int result = data * data;
        printIntLine(result);
    }
}
