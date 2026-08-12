/*
 * Rule: ARR30-C
 * Status: PASS - Should NOT trigger ARR30-C violation
 */

/*
 * Reason: an `enum` constant used as an array index is a compile-time
 * constant, not a runtime-variable index -- indexing a fixed-size lookup
 * table with it (`buttonState[MOUSE_BUTTON_LEFT]`) needs no bounds guard
 * when every enumerator is provably within range (task 443).
 */

typedef enum {
    MOUSE_BUTTON_LEFT = 0,
    MOUSE_BUTTON_RIGHT = 1,
    MOUSE_BUTTON_MIDDLE = 2,
} MouseButton;

#define MAX_MOUSE_BUTTONS 8

char buttonState[MAX_MOUSE_BUTTONS];

void f(void)
{
    buttonState[MOUSE_BUTTON_LEFT] = 1;
    buttonState[MOUSE_BUTTON_RIGHT] = 0;
    buttonState[MOUSE_BUTTON_MIDDLE] = 1;
}
