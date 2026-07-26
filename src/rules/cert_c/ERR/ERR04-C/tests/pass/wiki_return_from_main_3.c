/*
 * Rule: ERR04-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <stdlib.h>
 
int main(int argc, char **argv) {
  /* ... */
  if (/* Something really bad happened */) {
    return EXIT_FAILURE;
  }
  /* ... */
  return EXIT_SUCCESS;
}