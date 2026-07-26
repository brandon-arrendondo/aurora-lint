/*
 * Rule: ERR04-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <stdlib.h>
/* ... */

if (/* Something really bad happened */) {
  _Exit(EXIT_FAILURE);
}