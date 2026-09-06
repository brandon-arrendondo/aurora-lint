/*
 * Rule: INT32-C
 * Source: testcases
 * Status: EXPECTED FAIL, by measurement rather than oversight. The operand is a
 * parameter, and the provenance gate now does reason about parameters via the
 * call graph -- but it judges this one BOUNDED, because the only caller in the
 * scan set is a taint-free `main`. That approximation is the gate's limit: the
 * prescan summaries carry per-function taint, not per-argument value ranges, so
 * `main` handing this function INT_MAX or SIZE_MAX/2 is unbounded in value yet
 * carries no taint. Detecting it needs per-call-site argument ranges joined
 * across callers into a summary field -- a distinct piece of work, and NOT a
 * reason to loosen the gate, which would restore the parameter false positives
 * the caller-set rule exists to avoid. Genuine violation; kept as evidence.
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