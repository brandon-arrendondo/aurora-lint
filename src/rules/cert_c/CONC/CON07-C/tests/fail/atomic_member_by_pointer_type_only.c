/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: FAIL - Should trigger CON07-C violation
 * Expect: count=3
 *
 * A write through a pointer is atomic only when both the pointer's type
 * and the object it points at declare the member atomic. A pointer to a
 * structure with an atomic member, made to point at an object whose type
 * declares the member plain, writes it plainly; so does a plain-typed
 * pointer to an object whose member is atomic; and a typedef'd pointer to
 * a plain member is read through its typedef and reported as the spelled
 * pointer is.
 */

#include <stdatomic.h>

struct counted {
  atomic_int refs;
};
struct plain {
  int refs;
};
typedef struct plain *plain_ptr;

static struct plain g;
static struct counted ga;
static struct plain h;

void retain(void) {
  struct counted *p = (struct counted *)&g;
  p->refs++;
}

void release(void) {
  struct plain *r = (struct plain *)&ga;
  r->refs--;
}

void bump(void) {
  plain_ptr q = &h;
  q->refs += 2;
}
