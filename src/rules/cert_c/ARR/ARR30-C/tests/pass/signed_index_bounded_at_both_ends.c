/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The index is bounded at both ends
 *
 * `data` is parsed by `atoi`, so it may be negative, and each upper-bound
 * test on it comes with a lower end: a `>= 0` or `> -1` test beside it, an
 * early return on a negative value, or a conversion to an unsigned type at
 * least as wide as `int`, under which a negative value fails the `< 10`
 * test too.
 */
#include <stdlib.h>

void both_in_one_condition(const char *text)
{
    int buffer[10] = {0};
    int data = atoi(text);
    if (data >= 0 && data < 10)
    {
        buffer[data] = 1;
    }
    if (data > -1 && data < 10)
    {
        buffer[data] = 2;
    }
}

void early_return_on_either_end(const char *text)
{
    int buffer[10] = {0};
    int data = atoi(text);
    if (data < 0 || data >= 10)
        return;
    buffer[data] = 1;
}

void unsigned_conversion(const char *text)
{
    int buffer[10] = {0};
    int data = atoi(text);
    if ((unsigned)data < 10)
    {
        buffer[data] = 1;
    }
}

void long_conversion(const char *text)
{
    int buffer[10] = {0};
    int data = atoi(text);
    if ((unsigned long)data < 10)
    {
        buffer[data] = 1;
    }
}
