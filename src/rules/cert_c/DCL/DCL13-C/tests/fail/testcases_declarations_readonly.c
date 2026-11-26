/*
 * Rule: DCL13-C
 * Source: testcases
 * Status: FAIL - Parameters judged by the definition, whatever their names
 * Expect: count=3
 *
 * Each parameter is reported where the definition leaves what it points to
 * unchanged, whatever the prototype calls it, or whether it names it at
 * all. A prototype alone is not reported.
 */

void copy_data(char *dest, char *src);

void log_read_data(char *read_buffer);

void tally(int *, int *counts);

void copy_data(char *dest, char *src) { dest[0] = src[0]; }

void log_read_data(char *buf) { (void)buf[0]; }

void tally(int *total, int *counts) { *total += counts[0]; }
