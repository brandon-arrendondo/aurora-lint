/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The index cannot be negative, or nothing shows it can
 *
 * An unsigned index read from input is never negative, so a test of its
 * upper end alone bounds the access. A counter that starts at 0 and an
 * int that holds a `strlen` result have no negative origin the analysis
 * sees, so their upper guards are credited too.
 */
#include <stdio.h>
#include <string.h>

extern int more(void);

void unsigned_index(void)
{
    unsigned data = 0;
    int buffer[10] = {0};
    if (fscanf(stdin, "%u", &data) != 1)
        return;
    if (data < 10)
    {
        buffer[data] = 1;
    }
}

void counter_from_zero(void)
{
    int buffer[10] = {0};
    for (int i = 0; more(); i++)
    {
        if (i < 10)
        {
            buffer[i] = 1;
        }
    }
}

void length_in_an_int(const char *s)
{
    char name[10];
    int n = strlen(s);
    if (n < 10)
    {
        name[n] = '\0';
    }
}
