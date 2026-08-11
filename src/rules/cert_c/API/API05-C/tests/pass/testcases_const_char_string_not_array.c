/*
 * Rule: API05-C
 * Source: testcases
 * Status: PASS - Should NOT trigger API05-C violation
 */

/*
 * Reason: a NUL-terminated `const char *` string is self-delimiting -- an
 * accompanying size_t param (e.g. a separate max-length limit) is not
 * evidence that the string itself should be a conformant array (task 190).
 */

#include <stddef.h>
extern size_t strnlen(const char *s, size_t maxlen);

void log_message(const char *msg, size_t max_len)
{
    (void)strnlen(msg, max_len);
}
