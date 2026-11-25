/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - Should not trigger CON07-C violation
 *
 * A pointer declared through a typedef is read through it: a write through
 * `SP p = &g` to a member the structure declares atomic, of an object
 * whose own type declares it atomic, is one atomic read-modify-write, and
 * so is `(*q)++` through a typedef'd pointer to an atomic object.
 */

#include <stdatomic.h>

struct counted {
  atomic_int refs;
};
typedef struct counted *counted_ptr;
typedef _Atomic int *atomic_int_ptr;

static struct counted g;
static atomic_int hits;

void retain(void) {
  counted_ptr p = &g;
  p->refs++;
}

void hit(void) {
  atomic_int_ptr q = &hits;
  (*q)++;
}
