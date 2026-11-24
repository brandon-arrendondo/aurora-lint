/*
 * Rule: INT08-C
 * Source: synthetic
 * Status: FAIL - the guard admits the value the square overflows
 *
 * `data` is 32767 and `llabs(data) >= 181` holds for it, so the square
 * runs with that value and does not fit in a short. Under strict, where
 * an int may have only 16 bits, the product is also reported for leaving
 * the int its operands promote to.
 */
#include <stdlib.h>

void printIntLine(int);

void admitted(void)
{
    short data = 32767;
    if (llabs((long long)data) >= 181)
    {
        short result = data * data;
        printIntLine(result);
    }
}
