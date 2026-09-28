/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: `extern int hits;` inside tick() names the file-scope object, not
 * a local, so tick() writes a global and has a side effect.
 */

#define TWICE(x) ((x) + (x))

int tick(void) {
    extern int hits;
    return ++hits;
}

int use_tick(void) {
    return TWICE(tick());
}
