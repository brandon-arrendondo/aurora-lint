/*
 * Rule: INT32-C
 * Source: regression
 * Status: PASS - the step the caller passes is a macro with one value
 * Settings: data_model=lp64
 *
 * The counterpart of static_sink_step_is_an_overridable_default.c: STEP is
 * -5 in every build, the sink's only caller passes it, and rand() is at
 * most RAND_MAX, so `x + step` fits.
 */
#include <stdlib.h>

#define STEP (-5)

static int sink(int step)
{
    int x = rand();
    return x + step;
}

int caller(void)
{
    return sink(STEP);
}
