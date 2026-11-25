/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - Should not trigger CON07-C violation
 *
 * An atomic operation on the object a function writes, or a compound
 * write to an object its own declaration makes atomic, is one atomic
 * read-modify-write, whatever else the function spells.
 */

#include <stdatomic.h>

static atomic_int hits;
static _Atomic long pending;

void on_hit(void) { atomic_fetch_add_explicit(&hits, 1, memory_order_relaxed); }

void on_done(void) {
  long seen = atomic_load(&pending);
  pending -= 1;
  (void)seen;
}

