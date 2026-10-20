/*
 * Rule: CON40-C
 * Source: testcases
 * Status: PASS - Should not trigger CON40-C violation
 *
 * A struct that has an _Atomic member is not itself atomic: its other
 * members are plain objects, and each atomic member is a different object.
 */

#include <stdatomic.h>

static struct config {
    int requests;
    int clients;
    _Atomic int liveclients;
    _Atomic int finished;
} config;

int pending(void) {
    return config.requests - config.clients * config.requests;
}

int done(void) {
    return config.liveclients + config.finished;
}
