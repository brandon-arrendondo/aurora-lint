/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: PASS - Should not trigger ARR39-C violation
 *
 * A byte count added to a pointer whose declared type points to bytes
 * scales once, however the pointer is reached: through a pointer to
 * pointer, a flexible array member, or a byte typedef.
 */

#include <stddef.h>

typedef unsigned char octet;

struct node {
  size_t size;
  unsigned char data[];
};

void consume(const unsigned char **buf) {
  *buf += sizeof(long);
}

unsigned char *child_slot(struct node *n, size_t pos) {
  return n->data + n->size + sizeof(struct node *) * pos;
}

octet *skip_header(octet *buf, size_t n) {
  return buf + n * sizeof(int);
}

char *string_table(char *image, unsigned short count, size_t n) {
  return image + sizeof(long) + count * sizeof(int) + n * sizeof(short);
}
