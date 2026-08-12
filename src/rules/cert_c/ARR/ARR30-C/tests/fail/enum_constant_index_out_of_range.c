/*
 * Rule: ARR30-C
 * Status: FAIL - Should trigger ARR30-C violation
 */

/*
 * Reason: resolving an enum constant's value must still catch a genuinely
 * out-of-range compile-time index (task 443), not just suppress every
 * enum-indexed access unconditionally.
 */

typedef enum {
    COLOR_RED = 0,
    COLOR_GREEN = 1,
    COLOR_BLUE = 2,
    COLOR_OVERFLOW = 10,
} Color;

int palette[3];

void f(void)
{
    palette[COLOR_OVERFLOW] = 1;
}
