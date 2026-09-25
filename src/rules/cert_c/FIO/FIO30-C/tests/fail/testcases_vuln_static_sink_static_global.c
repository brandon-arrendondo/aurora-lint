/*
 * Rule: FIO30-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO30-C violation
 */

/*
 * Rule: FIO30-C - Exclude user input from format strings
 * Status: FAIL
 * Reason: User input reaches a static sink through a static global that one
 * function writes and another reads (Juliet flow variant 45). The call into
 * the sink passes a local copied from the global, clean to a check that looks
 * at one body at a time.
 */

#include <stdarg.h>
#include <stdio.h>

static char *pending_format;

static void log_message(char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
}

static void flush_pending(void)
{
    char *data = pending_format;
    log_message(data, data);
}

void entry(void)
{
    char buf[100] = "";
    fgets(buf, sizeof(buf), stdin);
    pending_format = buf;
    flush_pending();
}
