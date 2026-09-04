/*
 * Rule: ARR00-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR00-C violation
 */

/*
 * Rule: ARR00-C - Understand how arrays work
 * Status: PASS
 * Reason: An ordinary scalar swap is not pointer subtraction. The provenance
 *         scan is textual, so `startAngle = endAngle; endAngle = tmp;`
 *         resolves each float to the other's NAME; only a type check on the
 *         operands themselves distinguishes this from two pointers into
 *         different arrays.
 *
 *         Distilled from raylib rshapes.c (DrawCircleSector).
 */

#include <stdio.h>

void draw_sector(float startAngle, float endAngle, int segments) {
    if (endAngle < startAngle) {
        float tmp = startAngle;
        startAngle = endAngle;
        endAngle = tmp;
    }

    float stepLength = (endAngle - startAngle) / (float)segments;
    printf("%f\n", stepLength);
}

int main(void) {
    draw_sector(90.0f, 0.0f, 36);
    return 0;
}
