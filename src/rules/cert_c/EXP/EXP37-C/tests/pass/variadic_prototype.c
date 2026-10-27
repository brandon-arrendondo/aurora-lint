/*
 * Rule: EXP37-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP37-C violation
 *
 * Declaring a variadic function is not a violation.
 */

int log_message(const char *fmt, ...);
