/*
 * Rule: ARR30-C
 * Status: PASS - Should NOT trigger ARR30-C violation
 */

/*
 * Reason: a single-sided `idx < MACRO_NAME` guard is just as valid a bounds
 * check as `idx < 10` -- it doesn't need a paired `>= 0` or `&&` to be safe
 * against an upper-bound overrun. This must hold whether the guarded index
 * is a plain local or (as here) a struct field (task 443): the macro name
 * is resolved and compared against the real buffer size either way.
 */

#define MAX_TOUCH_POINTS 10

typedef struct { int touchSlot; } Platform;
extern Platform platform;

int touchPosition[MAX_TOUCH_POINTS];

void f(void)
{
    if (platform.touchSlot < MAX_TOUCH_POINTS)
    {
        touchPosition[platform.touchSlot] = 1;
    }
}
