/*
 * Rule: INT10-C
 * Source: aurora_lint 1284 (hostap hostapd/config_file.c:4252)
 * Status: PASS - Should NOT trigger INT10-C violation
 *
 * The `%` of a `%d` conversion specifier is inside a string literal. An ERROR
 * region can swallow the quote delimiters, after which it reparses as a modulo
 * operator over the surrounding words. See ADR-0008.
 */

extern void log_msg(int level, const char *fmt, ...);

void report(int line)
{
    log_msg(1, "Line %d: Invalid bss_load_test", line);
}
