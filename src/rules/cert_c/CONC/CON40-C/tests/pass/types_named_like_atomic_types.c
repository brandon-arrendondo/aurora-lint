/*
 * Rule: CON40-C
 * Source: synthetic
 * Status: PASS - a member whose type is an aggregate holding an _Atomic
 * member is not itself atomic, and a type that is only named atomic_ is
 * whatever its own declaration makes it
 */

#include <stdatomic.h>

struct atomic_state {
  int x;
};

struct holder {
  struct {
    _Atomic int live;
    int dead;
  } inner;
  struct atomic_state st;
};

struct holder h;

int read_inner_plain_member(void) {
  return h.inner.dead + h.inner.dead;
}

int read_member_of_tagged_type(void) {
  return h.st.x + h.st.x;
}

typedef struct {
  volatile int counter;
} atomic_t;

atomic_t refs;

int read_counter(void) {
  return refs.counter + refs.counter;
}
