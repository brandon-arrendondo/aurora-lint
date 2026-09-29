/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: the mirror case. PASTE(reset) calls do_reset, which writes g, while
 * reset is pure. The pasted callee is not named, so via_paste is unproven,
 * never judged by the pure reset. Only the strict preset reports it.
 */

#define PASTE(n) do_##n(0)
#define TWICE(x) ((x) + (x))

int g;

int do_reset(int x) {
    g = x;
    return 0;
}

int reset(int x) {
    return x;
}

int via_paste(void) {
    return PASTE(reset);
}

int d(void) {
    return TWICE(via_paste());
}
