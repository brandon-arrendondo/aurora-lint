/*
 * Rule: INT08-C
 * Source: synthetic
 * Status: FAIL - a sqrt bound wide enough to admit the value that overflows
 * Settings: iec_60559_sqrt=true
 *
 * `(long)sqrt((double)2000000000)` is 44721, so the guard holds for
 * `data` = 30000 and the square, 900000000, does not fit in a short.
 */
#include <math.h>
#include <stdlib.h>

void printIntLine(int);

void admitted(void)
{
    short data = 30000;
    if (abs((long)data) <= (long)sqrt((double)2000000000))
    {
        short result = data * data;
        printIntLine(result);
    }
}
