/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - Should not trigger CON07-C violation
 *
 * A compound assignment or increment of an atomic object is one atomic
 * read-modify-write (C11 6.5.2.4p2, 6.5.16.2p3), whether the object is
 * declared `_Atomic`, `_Atomic(T)`, with a `<stdatomic.h>` name, through a
 * typedef, or reached through a pointer to an atomic object.
 */

#include <stdatomic.h>

typedef _Atomic unsigned atomic_mask;

static _Atomic int hits;
static atomic_int bytes;
static _Atomic(long) pending;
static atomic_mask mask;
static _Atomic int *const counter = &hits;

void on_hit(void) { hits++; }

void on_bytes(int n) { bytes += n; }

void on_done(void) { --pending; }

void on_mask(void) { mask |= 1u; }

void on_count(void) { (*counter)++; }
