/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: buf points to volatile data, but reading the member buf itself
 * (the pointer) is not a volatile access; id is not volatile at all.
 */

#include <assert.h>

struct dev {
    int id;
    volatile unsigned *buf;
};

void check(struct dev *d) {
    assert(d->buf != 0 && d->id >= 0);
}
