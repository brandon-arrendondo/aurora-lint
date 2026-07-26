/*
 * Rule: INT31-C
 * Source: wiki
 * Status: FAIL - Should trigger INT31-C violation
 */

#include <time.h>
 
void func(void) {
  time_t now = time(NULL);
  if (now != -1) {
    /* Continue processing */
  }
}