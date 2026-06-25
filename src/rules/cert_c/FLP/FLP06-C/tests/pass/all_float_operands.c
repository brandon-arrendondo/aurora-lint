/*
 * Rule: FLP06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FLP06-C violation
 */

/*
 * FLP06-C PASS Case: arithmetic whose operands are all floating-point.
 *
 * Regression guard for the raylib audit FP class (task 230): the old text
 * heuristic flagged float initializers lacking a literal '.'/'f' or a cast as
 * "integer arithmetic", even when every operand was a float param/local. With
 * operand typing, float*float / float+float / float-float is not integer
 * arithmetic and must stay silent.
 */

/* All operands are float parameters (raylib Lerp/Remap pattern). */
float lerp(float start, float end, float amount)
{
    float result = start + amount*(end - start);
    return result;
}

float remap(float value, float inputStart, float inputEnd, float outputStart, float outputEnd)
{
    float result = (value - inputStart)/(inputEnd - inputStart)*(outputEnd - outputStart) + outputStart;
    return result;
}

/* All operands are float locals. */
float magnitude(float dx, float dy)
{
    float value = (dx*dx) + (dy*dy);
    return value;
}
