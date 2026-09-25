/*
 * Rule: ENV30-C
 * Source: testcases
 * Status: FAIL - Should trigger ENV30-C violation
 */

/*
 * Rule: ENV30-C - Do not modify the object referenced by the return value
 *       of certain functions
 * Status: FAIL
 * Reason: Either branch of the conditional stores getenv()'s own pointer, and
 *         a cast does not copy the string. Writing through `home` modifies
 *         the environment.
 */

#include <stdlib.h>
#include <string.h>

void tidy(int use_tmp)
{
    char *home = use_tmp ? (char *)getenv("TMPDIR") : getenv("HOME");
    if (home != NULL) {
        strcat(home, "/");
    }
}
