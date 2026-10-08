/*
 * Rule: EXP33-C
 * Source: wiki
 * Status: EXPECTED FAIL - Known limitation: the CERT noncompliant example is
 * reported only once `resize_array` is declared as following realloc's
 * contract (`[environment.allocators] resize_array = "realloc"`, or
 * `--allocator resize_array=realloc`). A function whose body wraps an
 * allocator is not treated as one until the project says so. The declared
 * case is asserted by tests/cli_integration.rs.
 */

#include <stdlib.h>
#include <stdio.h>
enum { OLD_SIZE = 10, NEW_SIZE = 20 };
 
int *resize_array(int *array, size_t count) {
  if (0 == count) {
    return 0;
  }
 
  int *ret = (int *)realloc(array, count * sizeof(int));
  if (!ret) {
    free(array);
    return 0;
  }
 
  return ret;
}
 
void func(void) {
 
  int *array = (int *)malloc(OLD_SIZE * sizeof(int));
  if (0 == array) {
    /* Handle error */
  }
 
  for (size_t i = 0; i < OLD_SIZE; ++i) {
    array[i] = i;
  }
 
  array = resize_array(array, NEW_SIZE);
  if (0 == array) {
    /* Handle error */
  }
 
  for (size_t i = 0; i < NEW_SIZE; ++i) {
    printf("%d ", array[i]);
  }
}