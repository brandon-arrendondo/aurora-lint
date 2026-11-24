/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - integer bounds spelled through typedefs and enumerations
 * Settings: iec_60559_sqrt=true, data_model=lp64
 *
 * A cast to an integer typedef, an object of an integer typedef or of an
 * enumerated type, and type specifiers in any order are all integer: each
 * guard bounds `data` to -181..181, and the square fits in a short.
 */
#include <limits.h>
#include <math.h>
#include <stdlib.h>

typedef int myint;
typedef long mylong;
enum limit { LIMIT = 181 };

void printIntLine(int);

void cast_to_an_integer_typedef(short data)
{
    if (abs(data) <= (myint)181)
    {
        short result = data * data;
        printIntLine(result);
    }
}

void object_of_an_integer_typedef(short data, myint bound)
{
    if (bound < 0 || bound > 181)
        return;
    if (abs(data) <= bound)
    {
        short result = data * data;
        printIntLine(result);
    }
}

void object_of_an_enumerated_type(short data, enum limit bound)
{
    if (bound < 0 || bound > 181)
        return;
    if (abs(data) <= bound)
    {
        short result = data * data;
        printIntLine(result);
    }
}

void square_root_through_a_typedef(short data)
{
    if (labs((long)data) <= (long)sqrt((double)(myint)SHRT_MAX))
    {
        short result = data * data;
        printIntLine(result);
    }
}

void result_cast_to_a_typedef(short data)
{
    if (labs((long)data) <= (mylong)sqrt((double)SHRT_MAX))
    {
        short result = data * data;
        printIntLine(result);
    }
}

void specifiers_in_another_order(unsigned char data)
{
    if (abs((short unsigned)data) <= 181)
    {
        short result = data * data;
        printIntLine(result);
    }
}
