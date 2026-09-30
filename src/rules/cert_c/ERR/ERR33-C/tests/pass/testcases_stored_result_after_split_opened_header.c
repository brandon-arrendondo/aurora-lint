/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: PASS
 * Reason: strrchr's result is tested on the next line. The test is found
 *         only if the function is read as one: the header before it is
 *         split across #ifdef/#else, each arm opening the body the single
 *         closing brace after #endif ends.
 */

#include <string.h>
int f(int n, const char *s)
{
    char *p;
    int r = 0;
#ifdef WITH_UNIX
    if (n < 0 || n > 65535) {
#else
    if (n < 1 || n > 65535) {
#endif
        r = 1;
    }
    p = strrchr(s, ':');
    if (p) {
        r = 2;
    }
    return r;
}
