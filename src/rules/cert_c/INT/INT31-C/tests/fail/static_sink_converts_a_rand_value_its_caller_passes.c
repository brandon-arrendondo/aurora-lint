/*
 * Rule: INT31-C
 * Source: regression
 * Status: FAIL - the size converted to size_t comes from rand()
 *
 * The static sink's only caller passes rand()'s result, which inline would
 * be reported as an unchecked conversion; through the parameter it is the
 * same value.
 */
#include <stdlib.h>

static void sink(int data)
{
    char *p = malloc(data);
    free(p);
}

void caller(void)
{
    int data = rand();
    sink(data);
}
