/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: FAIL - Should trigger CON07-C violation
 * Expect: count=3
 *
 * An object is atomic by its own declaration, not by an atomic spelling
 * elsewhere in the function that writes it. A local structure type with
 * an atomic member does not make a member of a plain object atomic, an
 * unrelated atomic local does not make a plain counter atomic, and an
 * atomic load of one object does not make an increment of another one
 * atomic.
 */

#include <stdatomic.h>

struct plain {
  int refs;
};

static struct plain g;
static int counter;
static int nesting;
static atomic_int acquiring;

void retain(void) {
  struct counted {
    _Atomic int refs;
  };
  g.refs++;
}

void tick(void) {
  _Atomic int local = 0;
  counter++;
  (void)local;
}

void yield(void) {
  if (atomic_load_explicit(&acquiring, memory_order_relaxed))
    return;
  nesting++;
}
