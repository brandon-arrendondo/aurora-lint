/*
 * Rule: ERR33-C
 * Status: PASS - timespec_get() returns its base argument on success and 0
 * on failure, so testing the result against TIME_UTC detects the failure.
 */

#include <time.h>

int now(struct timespec *ts) {
    int r = timespec_get(ts, TIME_UTC);
    if (r != TIME_UTC) {
        return -1;
    }
    return 0;
}
