/*
 * Rule: ARR30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR30-C violation
 */

/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: PASS
 * Reason: The gamepad index parameter is bounds-checked before being used
 * to subscript the struct member array, for both a pointer-returning
 * accessor (const char *) and a primitive-returning accessor (int).
 */

#define MAX_GAMEPADS 4

struct GamepadState {
    char name[MAX_GAMEPADS][64];
    int axisCount[MAX_GAMEPADS];
};

struct GamepadState CORE;

const char *GetGamepadName(int gamepad) {
    if (gamepad < 0 || gamepad >= MAX_GAMEPADS) {
        return "";
    }
    return CORE.name[gamepad];
}

int GetGamepadAxisCount(int gamepad) {
    if (gamepad < 0 || gamepad >= MAX_GAMEPADS) {
        return 0;
    }
    return CORE.axisCount[gamepad];
}
