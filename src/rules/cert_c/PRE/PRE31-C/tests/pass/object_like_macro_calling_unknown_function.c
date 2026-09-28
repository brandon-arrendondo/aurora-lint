/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: NOW expands to a call to get_tick, which no scanned file defines,
 * so stamp() is unproven, not pure: reported only under the strict preset.
 */

#define NOW get_tick()
#define TWICE(x) ((x) + (x))

int get_tick(void);

static int stamp(void) {
    return NOW;
}

int use_stamp(void) {
    return TWICE(stamp());
}
