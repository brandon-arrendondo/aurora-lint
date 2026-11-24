/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: FAIL - a parameter named used or retain is no keep-alive attribute
 */
#include <string.h>

static void grow(char *buffer, unsigned long used) /* Expect: here */
{
    memset(buffer, 0, used);
}

static void keep(int retain) /* Expect: here */
{
    (void)retain;
}

void api(void)
{
}
