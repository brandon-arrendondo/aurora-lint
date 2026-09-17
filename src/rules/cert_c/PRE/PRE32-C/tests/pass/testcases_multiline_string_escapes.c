/*
 * Rule: PRE32-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE32-C violation
 */

/*
 * Rule: PRE32-C - Do not use preprocessor directives in invocations of function-like macros
 * Status: PASS
 * Reason: An ordinary multi-line function call whose string-literal
 * arguments contain escape sequences (\n, \") is not a preprocessor
 * directive - the presence of a backslash and a newline somewhere in the
 * argument text is not evidence of one. Modeled on a real false positive
 * found in pure-ftpd's tls_extcert.c / altlog.c.
 */

#include <stdio.h>

void format_line(char *line, size_t size, const char *host, const char *account) {
    snprintf(line, size,
              "%s - %s [%s] \"%s %s\" 200 %llu\n",
              host, account, "date",
              "GET", "file",
              0ULL);
}

int main(void) {
    char buf[128];
    format_line(buf, sizeof buf, "host", "account");
    return 0;
}
