/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: PASTE(reset) calls do_reset, not reset: token pasting makes the
 * callee a name no token in the body spells. The callee is not named, so
 * via_paste is unproven, never blamed on reset's write. Only the strict
 * preset reports it.
 */

#define PASTE(n) do_##n(0)
#define TWICE(x) ((x) + (x))

int g;

int do_reset(int x) {
    return x;
}

int reset(int x) {
    g = x;
    return 0;
}

int via_paste(void) {
    return PASTE(reset);
}

int d(void) {
    return TWICE(via_paste());
}
