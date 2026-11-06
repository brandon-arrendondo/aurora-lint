/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A call may rewrite a file-scope index declared in an unread header
 * Expect: count=1
 *
 * `gi` is declared in a header the scan does not read, so it is a
 * file-scope object `refresh` may assign.
 */

#include "other.h"

int buf[4];

void refresh(void);

int element(void)
{
    gi = 2;
    refresh();
    return buf[gi]; /* Expect: here */
}
