/*
 * Rule: CON09-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON09-C violation
 */

#include <stdatomic.h>
#include <threads.h>
 
static atomic_int array[];
static mtx_t array_mutex;

void func(void) {
  size_t index;
  int value;
  if (thrd_success != mtx_lock(&array_mutex)) {
    /* Handle error */
  }
  find_max_element(array, &index, &value);
  /* ... */
  if (!atomic_compare_exchange_strong(array[index], &value, 0)) {
    /* Handle error */
  }
  if (thrd_success != mtx_unlock(&array_mutex)) {
    /* Handle error */
  }
}