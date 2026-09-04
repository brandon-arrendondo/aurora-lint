/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR36-C violation
 *
 * Regression test for task 769: ARR36-C fired on operands that are not
 * pointers at all.
 *
 * PointerAnalyzer type-gates parameters and declarations, but process_assignment
 * gated nothing -- any `x = y` recorded a base for x. An ordinary scalar swap
 * therefore put both names in the tracked map, and the arithmetic below them was
 * reported as pointer subtraction between different arrays. Taken from raylib's
 * DrawCircleSector, which has no pointer anywhere in the function and produced
 * 18 findings.
 */

#include <math.h>

/* Three floats and a swap: nothing here is a pointer. */
float sector_step(float radius, float startAngle, float endAngle, int segments)
{
    if (endAngle < startAngle) {
        float tmp = startAngle;
        startAngle = endAngle;
        endAngle = tmp;
    }

    if (segments <= 0)
        segments = (int)ceilf((endAngle - startAngle) / 90.0f);

    return (endAngle - startAngle) / (float)segments * radius;
}

/* Integers, including a comparison against a macro constant. */
#define MAX_PARAMETERS 128

int clamp_param(int width, int max_param)
{
    if (width >= MAX_PARAMETERS)
        return -1;
    if (width >= max_param)
        max_param = width;

    return max_param - width;
}
