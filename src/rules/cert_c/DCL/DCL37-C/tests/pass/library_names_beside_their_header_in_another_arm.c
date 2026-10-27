/*
 * Rule: DCL37-C
 * Status: PASS - the file includes <stdbool.h> only in one arm of an #if
 * chain and declares `bool`, `false` and `true` in another, so no build both
 * includes the header and has the declaration.
 */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#include <stdbool.h>
#elif !defined(bool)
typedef enum bool { false = 0, true = !false } bool;
#endif

bool ready(int n) { return n > 0 ? true : false; }
