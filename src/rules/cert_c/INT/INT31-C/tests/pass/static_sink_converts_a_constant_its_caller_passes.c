/*
 * Rule: INT31-C
 * Source: regression
 * Status: PASS - the size converted to size_t is a constant its caller passes
 *
 * The counterpart of static_sink_converts_a_rand_value_its_caller_passes.c.
 */
#include <stdlib.h>

static void sink(int data)
{
    char *p = malloc(data);
    free(p);
}

void caller(void)
{
    int data = 16;
    sink(data);
}
