/*
 * Rule: ENV30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ENV30-C violation
 *
 * printf/fprintf were already recognized as safe (they only read their
 * arguments); this pins down that the wider printf family added via
 * call_roles::is_printf_family (task 499) -- vprintf and friends -- is
 * recognized too, so passing a protected variable as vprintf's first
 * (format) argument isn't wrongly flagged as "may modify it".
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void report(const char *unused, ...) {
    char *user = getenv("USER");
    va_list args;

    if (user != NULL) {
        va_start(args, unused);
        /* COMPLIANT: vprintf only reads its first (format) argument */
        vprintf(user, args);
        va_end(args);
    }
}

int main(void) {
    setenv("USER", "testuser", 1);
    report(NULL);
    return 0;
}
