/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A signed index is bounded from above only
 * Expect: count=5
 *
 * `data` is an int read from input, parsed by `atoi`, or set to -1 on a
 * path that reaches the access, so it may be negative. A test of its upper
 * end, whether it encloses the access, returns early before it, or clamps
 * the index, leaves `buffer[data]` free to write before the array.
 */
#include <stdio.h>
#include <stdlib.h>

void enclosing_guard(void)
{
    int data = -1;
    int buffer[10] = {0};
    if (fscanf(stdin, "%d", &data) != 1)
        return;
    if (data < 10)
    {
        buffer[data] = 1; /* Expect: here */
    }
}

void early_return(void)
{
    int data = -1;
    int buffer[10] = {0};
    if (fscanf(stdin, "%d", &data) != 1)
        return;
    if (data >= 10)
        return;
    buffer[data] = 1; /* Expect: here */
}

void clamp(void)
{
    int data = -1;
    int buffer[10] = {0};
    if (fscanf(stdin, "%d", &data) != 1)
        return;
    if (data > 9)
        data = 9;
    buffer[data] = 1; /* Expect: here */
}

void parsed(const char *text)
{
    int buffer[10] = {0};
    int data = atoi(text);
    if (data < 10)
    {
        buffer[data] = 1; /* Expect: here */
    }
}

void negative_on_one_path(int c)
{
    int buffer[10] = {0};
    int data = -1;
    if (c)
        data = 7;
    if (data < 10)
    {
        buffer[data] = 1; /* Expect: here */
    }
}
