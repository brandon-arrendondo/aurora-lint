/*
 * Rule: FIO30-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO30-C violation
 */

/*
 * Rule: FIO30-C - Exclude user input from format strings
 * Status: FAIL
 * Reason: A static sink's only caller hands it a value returned by a local
 * function that reads user input (Juliet flow variant 42). The caller's own
 * body calls no input function, so a check that looks at one body at a time
 * sees a clean argument; every caller of a static function is in this file,
 * where the returned taint is visible.
 */

#include <stdarg.h>
#include <stdio.h>

static char *read_input(char *buf)
{
    fgets(buf, 100, stdin);
    return buf;
}

static void log_message(char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
}

void entry(void)
{
    char buf[100] = "";
    char *data = read_input(buf);
    log_message(data, data);
}
