/*
 * Rule: INT32-C
 * Source: synthetic
 * Status: FAIL - a short as wide as an int may be INT_MIN
 * Settings: data_model=lp64, int_bits=16, short_bits=16
 * Expect: count=1
 *
 * Where short and int are both 16 bits, a short may hold INT_MIN, and abs
 * of it is not representable.
 */
#include <stdlib.h>

int short_argument(short s)
{
    return abs(s);
}
