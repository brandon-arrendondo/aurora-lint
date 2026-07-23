/*
 * Rule: CON09-C
 * Source: wiki
 * Status: FAIL - Should trigger CON09-C violation
 */

#include <stdatomic.h>
 
/*
 * Sets index to point to index of maximum element in array
 * and value to contain maximum array value.
 */
void find_max_element(atomic_int array[], size_t *index, int *value);

static atomic_int array[];

void func(void) {
  size_t index;
  int value;
  find_max_element(array, &index, &value);
  /* ... */
  if (!atomic_compare_exchange_strong(array[index], &value, 0)) {
    /* Handle error */
  }
}