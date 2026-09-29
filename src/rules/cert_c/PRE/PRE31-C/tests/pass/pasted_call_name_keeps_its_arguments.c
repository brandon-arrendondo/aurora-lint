/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE31-C violation
 *
 * One configuration routes the call to a workaround by pasting a prefix
 * onto it. `##` takes only the call's first token, so the rescan sees
 * `workaround_snprintf(buf, size, "%d", n)`: a different function, but its
 * arguments are evaluated exactly once, as in the other two arms.
 */

#include <stddef.h>
#include <stdio.h>

int workaround_snprintf(char *str, size_t size, const char *format, ...);

#if SNPRINTF_TYPE < 0
#define SNCHECK(CALL, SIZE) ((CALL) < 0)
#elif SNPRINTF_TYPE == 4
#define SNCHECK(CALL, SIZE) ((CALL) >= ((int) (SIZE)))
#else
#define SNCHECK(CALL, SIZE) (workaround_ ## CALL)
#endif

int format_count(char *buf, size_t size, int n)
{
    if (SNCHECK(snprintf(buf, size, "%d", n), size) != 0) {
        return -1;
    }
    return 0;
}
