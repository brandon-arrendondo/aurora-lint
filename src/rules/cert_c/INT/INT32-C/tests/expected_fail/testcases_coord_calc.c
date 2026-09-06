/*
 * Rule: INT32-C
 * Source: testcases
 * Status: EXPECTED FAIL - Known limitation: the operand here is a function
 * parameter (or a local with no traced taint source), and INT32-C's opt-in
 * provenance gate (has_risky_operand_provenance, backed by int_provenance)
 * treats that as bounded local state, so the signed overflow is not
 * reported. That gate is what removes the bounded-counter false positives
 * on real code; flagging every unconstrained parameter is the noise it
 * exists to avoid. Detecting this needs caller-side bounds reasoning, not
 * a louder gate. The fixture is a genuine INT32-C violation and stays as
 * tracked evidence of the trade.
 */

/*
 * Rule: INT32-C - Ensure that operations on signed integers do not result in overflow
 * Status: EXPECTED FAIL
 * Reason: Coordinate calculation can overflow when scaling or transforming coordinates
 */

#include <limits.h>
#include <stdio.h>

typedef struct {
    int x, y;
} Point;

Point scale_point(Point p, int scale_factor) {
    Point result;
    // Extract to locals so INT32-C can resolve types
    // (field_expression types can't be resolved without struct definitions)
    int px = p.x;
    int py = p.y;
    // VIOLATION: multiplication can overflow
    result.x = px * scale_factor;
    result.y = py * scale_factor;
    return result;
}

int main() {
    Point original = {1000000, 1000000};
    int scale = 3000;

    Point scaled = scale_point(original, scale);

    printf("Original: (%d, %d)\n", original.x, original.y);
    printf("Scaled: (%d, %d)\n", scaled.x, scaled.y);

    return 0;
}