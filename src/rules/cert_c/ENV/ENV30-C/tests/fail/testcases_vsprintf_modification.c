/*
 * Rule: ENV30-C
 * Source: testcases
 * Status: FAIL - Should trigger ENV30-C violation
 *
 * vsprintf/vsnprintf write to their first (destination) argument exactly
 * like sprintf/snprintf. Guards is_modification_function's classification
 * of them (task 499): passing a getenv() result as that destination must
 * still be flagged even after is_safe_function folds the full printf
 * family in via call_roles::is_printf_family.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void unsafe_vsprintf_modification(const char *fmt, ...) {
    char *env_user = getenv("USER");
    va_list args;

    if (env_user != NULL) {
        va_start(args, fmt);
        /* VIOLATION: vsprintf overwrites the getenv() buffer */
        vsprintf(env_user, fmt, args);
        va_end(args);
    }
}

int main(void) {
    setenv("USER", "testuser", 1);
    unsafe_vsprintf_modification("modified_%s", "user");
    return 0;
}
