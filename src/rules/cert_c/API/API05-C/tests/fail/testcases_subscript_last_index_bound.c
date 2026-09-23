/*
 * Rule: API05-C
 * Source: testcases
 * Status: FAIL - Should trigger API05-C violation
 */

/*
 * Reason: `buf[len - 1]` is the common last-valid-index bounds-check idiom
 * -- len genuinely bounds buf's size here.
 */

#include <stddef.h>

void terminate(char *buf, size_t len)
{
    buf[len - 1] = '\0';
}
