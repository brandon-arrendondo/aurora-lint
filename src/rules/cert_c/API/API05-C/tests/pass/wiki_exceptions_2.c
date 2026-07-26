/*
 * Rule: API05-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <stddef.h>
  
#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L || defined(__STDC_NO_VLA__)
#define N(x)
#else
#define N(x)  (x)
#endif
  
int f(size_t n, int a[N(n)]);