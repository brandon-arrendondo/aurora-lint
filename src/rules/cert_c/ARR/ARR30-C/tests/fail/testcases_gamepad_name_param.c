/*
 * Rule: ARR30-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR30-C violation
 */

/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: FAIL
 * Reason: Unvalidated function-parameter index into a struct member array,
 * where the enclosing function's return type is a pointer (char *) rather
 * than a primitive integer. The array subscript itself is identical in
 * shape to the int-returning case below (task 239) - the element type of
 * the accessed array, and the pointer-typed return of the enclosing
 * function, must not change whether the unvalidated index is flagged.
 */

#define MAX_GAMEPADS 4

struct GamepadState {
    char name[MAX_GAMEPADS][64];
    int axisCount[MAX_GAMEPADS];
};

struct GamepadState CORE;

// Pointer-returning accessor - previously missed because the function's
// return type (const char *) wraps the function_declarator in a
// pointer_declarator, which the naive parameter lookup didn't unwrap.
const char *GetGamepadName(int gamepad) {
    return CORE.name[gamepad];
}

// Structurally identical int-returning accessor - was already flagged.
int GetGamepadAxisCount(int gamepad) {
    return CORE.axisCount[gamepad];
}
