/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: PASS - Should not trigger ARR39-C violation
 *
 * A byte count divided by the element size is an element count, so adding
 * it to the pointer scales once: the sizeof divides rather than
 * multiplies.
 */

#include <stddef.h>

unsigned long *back_one_page(unsigned long *p) {
  p -= 4096 / sizeof(unsigned long);
  return p;
}

unsigned long *skip_bytes(unsigned long *p, size_t len) {
  p += len / sizeof(unsigned long);
  return p;
}

int *end_of(int *buffer, size_t sz) {
  return buffer + sz / sizeof (*buffer);
}

size_t probe(size_t *buf, size_t i, size_t size, size_t nchecks) {
  return buf[i * (size / sizeof(size_t) / nchecks)];
}

int *elements_of_bytes(int *ptr, size_t n) {
  return ptr + n * sizeof(int) / sizeof(int);
}

int *past_the_end(void) {
  static int table[8];
  return table + sizeof(table) / sizeof(table[0]);
}

int *slots_in(int *ptr, size_t buf_size) {
  return ptr + buf_size / sizeof(int);
}
