/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A call cannot write a static index only this function assigns
 *
 * `slot` is static and no other function of the file assigns it, so the
 * call to `stamp`, defined elsewhere, cannot change it: the access is in
 * bounds after the wrap.
 */

#define SLOTS 4

long stamp(long now, long then);

static unsigned int slot;
static long store[SLOTS];

long record(long now)
{
    int wrapped = 0;
    long delta;
    if (++slot >= SLOTS) {
        wrapped = 1;
        slot = 0;
    }
    if (wrapped) {
        delta = stamp(now, 0);
        delta -= store[slot];
    } else {
        delta = now - store[slot];
    }
    return delta;
}
