/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - a non-null pointer may convert to an unsigned char of 0, so the test proves nothing about s
 */

#include <stdint.h>
#include <stdlib.h>

char *get(int);

int narrowing_cast(void)
{
    char *s;
    if ((unsigned char)(uintptr_t)(s = get(1)) == 0 || *s == 0)
        return 1;
    return 0;
}
