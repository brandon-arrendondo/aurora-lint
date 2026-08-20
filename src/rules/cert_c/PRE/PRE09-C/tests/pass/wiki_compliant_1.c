/*
 * Rule: PRE09-C
 * Source: wiki
 * Status: PASS - Should NOT trigger PRE09-C violation
 */

#include <stdio.h>
#ifndef __USE_ISOC11
  /* Reimplements vsnprintf() */
  #include "my_stdio.h"
#endif
