/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: PASS - Should not trigger ARR39-C violation
 *
 * Arithmetic on a pointer to void, a GNU extension, moves by bytes, so a
 * byte count added to it scales once, whether the pointer is declared so
 * or cast to it.
 */

#include <stddef.h>

struct cache;

void *entry_at(struct cache *cache, size_t offset) {
  return (void *)cache + offset;
}

void *skip_ints(void *buf, size_t n) {
  return buf + n * sizeof(int);
}

void *after_record(int *record_ptr, size_t n) {
  return (void *)record_ptr + n * sizeof(int);
}
