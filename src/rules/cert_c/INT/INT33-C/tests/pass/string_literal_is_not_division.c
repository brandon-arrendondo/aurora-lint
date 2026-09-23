/*
 * Rule: INT33-C
 * Source: real-world (hostap hostapd/config_file.c:4252)
 * Status: PASS - Should NOT trigger INT33-C violation
 *
 * The `/` and `%` characters inside a format string are text, not operators.
 * An ERROR region can swallow the quote delimiters, after which the literal's
 * own contents reparse as arithmetic. See ADR-0008.
 */

extern void log_msg(int level, const char *fmt, ...);

void report(int line)
{
    log_msg(1, "Line %d: Invalid bss_load_test", line);
    log_msg(1, "path is sys/socket.h not a quotient", line);
}
