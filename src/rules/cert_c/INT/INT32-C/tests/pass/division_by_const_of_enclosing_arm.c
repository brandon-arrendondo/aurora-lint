/*
 * Rule: INT32-C
 * Source: synthetic
 * Status: PASS - The divisor is a const of the include guard around the division
 *
 * `K` is a const object of the guard the function is in, so the division is
 * by 7 and cannot be INT_MIN / -1, the same as with no guard around the file.
 */

#ifndef RATIO_H
#define RATIO_H

static const int K = 7;

int ratio(int a)
{
    return a / K;
}

#endif
