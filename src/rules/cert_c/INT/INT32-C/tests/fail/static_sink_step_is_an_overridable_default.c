/*
 * Rule: INT32-C
 * Source: regression
 * Status: FAIL - the step the caller passes is only an #ifndef default
 * Settings: data_model=lp64
 *
 * `x` comes from rand(), so the addition is checked. Had STEP one value in
 * every build, it would prove `x + step` fits (see
 * static_sink_step_is_a_fixed_macro.c). But STEP is defined only when the
 * build has not defined it, and a build passing -DSTEP=INT_MAX gets another
 * value, so no value of it is a proof (ADR-0010, ADR-0011).
 */
#include <stdlib.h>

#ifndef STEP
#define STEP (-5)
#endif

static int sink(int step)
{
    int x = rand();
    return x + step;
}

int caller(void)
{
    return sink(STEP);
}
