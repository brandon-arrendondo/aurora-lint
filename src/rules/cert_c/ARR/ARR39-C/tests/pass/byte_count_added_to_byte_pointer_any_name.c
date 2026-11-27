/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: PASS - Should not trigger ARR39-C violation
 *
 * A byte count added to a pointer that points to bytes scales once,
 * whatever its name: a typedef'd byte pointer, a struct member and an
 * array element's member.
 */

#include <stddef.h>

typedef unsigned char *octets_t;

struct frame {
  unsigned char *payload;
  long count;
};

unsigned char *advance_octets(octets_t q, size_t n) {
  return q + n * sizeof(int);
}

unsigned char *payload_at(struct frame *f, size_t n) {
  return f->payload + n * sizeof(int);
}

unsigned char *payload_in(struct frame frames[], size_t i, size_t n) {
  return frames[i].payload + n * sizeof(int);
}

void step_octets(octets_t q, size_t n) {
  q += n * sizeof(int);
  (void)q;
}

unsigned char read_payload(struct frame *f, size_t n) {
  return f->payload[n * sizeof(int)];
}

long scaled_count(struct frame *f, size_t n) {
  return f->count + n * sizeof(int);
}
