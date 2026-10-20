/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * An _Atomic member is an atomic object, reached by its member path:
 * reading it twice in one expression is two atomic reads.
 */

#include <stdatomic.h>

struct stats {
    int requests;
    _Atomic long total;
};

static struct stats global_stats;

long average(struct stats *s) {
    return s->total * s->total / s->requests;
}

long doubled(void) {
    return global_stats.total + global_stats.total;
}
