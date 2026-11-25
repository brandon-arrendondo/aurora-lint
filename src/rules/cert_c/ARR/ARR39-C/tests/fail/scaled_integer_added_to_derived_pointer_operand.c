/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: FAIL - Should trigger ARR39-C violation
 * Expect: count=5
 *
 * An operand is a pointer by its type, however that type is reached: a
 * local and a parameter of a pointer typedef, a sum of a dereferenced
 * pointer to pointer, an element of an array of pointers, and an array
 * member. Each scales twice when a scaled integer is added to it.
 */

#include <stddef.h>

typedef int *int_ref;

struct record {
  long data[4];
};

int typedef_local(int_ref origin, size_t n) {
  int_ref p = origin;
  return *(p + n * sizeof(int));
}

int typedef_parameter(int_ref p, size_t n) {
  return *(p + n * sizeof(int));
}

int *through_pointer_to_pointer(int **pp, size_t i, size_t n) {
  return *pp + i + n * sizeof(int);
}

int *element_of_pointer_array(int *arr[], size_t k, size_t i, size_t n) {
  return arr[k] + i + n * sizeof(int);
}

long *array_member(struct record *s, size_t i, size_t n) {
  return s->data + i + n * sizeof(long);
}
