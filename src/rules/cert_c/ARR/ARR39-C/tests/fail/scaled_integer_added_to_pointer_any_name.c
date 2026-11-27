/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: FAIL - Should trigger ARR39-C violation
 * Expect: count=6
 *
 * A pointer operand is known by its type, not its name: a typedef'd
 * pointer, a struct member and an array element's member each point to
 * int, so adding a scaled integer to one scales twice.
 */

#include <stddef.h>

typedef int *cursor_t;

struct ring {
  int *slots;
};

int *advance_cursor(cursor_t q, size_t n) {
  return q + n * sizeof(int);
}

int *slot_of(struct ring *r, size_t n) {
  return r->slots + n * sizeof(int);
}

int *slot_in(struct ring rings[], size_t i, size_t n) {
  return rings[i].slots + n * sizeof(int);
}

void step_cursor(cursor_t q, size_t n) {
  q += n * sizeof(int);
  (void)q;
}

void step_slot(struct ring *r, size_t n) {
  r->slots += n * sizeof(int);
}

int read_slot(struct ring *r, size_t n) {
  return r->slots[n * sizeof(int)];
}
