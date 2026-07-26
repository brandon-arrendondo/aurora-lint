/*
 * Rule: ERR04-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <stdlib.h>
#include <stdio.h>

int write_data(void) {
  const char *filename = "hello.txt";
  FILE *f = fopen(filename, "w");
  if (f == NULL) {
    /* Handle error */
  }
  fprintf(f, "Hello, World\n");
  /* ... */
  exit(EXIT_FAILURE); /* Writes data and closes f */
  /* ... */
  return 0;
}

int main(void) {
  write_data();
  return EXIT_SUCCESS;
}