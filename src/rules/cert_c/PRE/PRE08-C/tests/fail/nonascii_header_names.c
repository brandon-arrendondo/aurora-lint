/*
 * Rule: PRE08-C
 * Status: FAIL - Should trigger PRE08-C violation
 * Description: The comparison is over the first eight bytes, cut back to a
 * character boundary, so these two names collide there. A multibyte character
 * straddling the eighth byte must not panic the cut.
 */
#include "aééééé.h"
#include "aééééé2.h"
