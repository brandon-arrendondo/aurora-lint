/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: FAIL - Should trigger ARR30-C violation
 * Reason: iscntrl() is TRUE for '\0', so it is the one <ctype.h> classifier
 *         that does NOT stop the walk at the terminator. Accepting it with
 *         the rest would suppress a genuine over-read, which is why the
 *         NUL-false classifier list is enumerated rather than matched as
 *         "any call named is*".
 */

#include <ctype.h>

int sum_control(const char *p) {
    int n = 0;
    while (iscntrl(*p)) {
        n += *p;
        p++;
    }
    return n;
}
