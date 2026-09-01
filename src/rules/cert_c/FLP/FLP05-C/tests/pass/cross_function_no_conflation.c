/*
 * Rule: FLP05-C
 * Source: task 418 (task-389 sweep, whole-file var_types conflation)
 * Status: PASS - Should NOT trigger FLP05-C violation
 *
 * `var_types` was previously built by a single whole-translation-unit walk
 * with no per-function reset. `process_declaration` only tracks
 * `declaration`-kind local variables, never function parameters, so a
 * same-named parameter in a later function inherited whatever type an
 * earlier, unrelated function's local variable of the same name had left
 * behind. Here `func_a`'s local `float x` must not leak into `func_b`'s
 * unrelated `int x` parameter and flag its multiply by a small constant.
 */

void func_a(void) {
    float x;
    x = 1.0f;
}

void func_b(int x) {
    double y = x * 7e-45;
    (void)y;
}
