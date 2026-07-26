/*
 * Rule: MSC12-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC12-C violation
 */

#include <stdio.h>
 
for (int i = 0; i < 10; ++i) {
  printf("i is %d", i);
  continue;  // this is meaningless; the loop would continue anyway
}