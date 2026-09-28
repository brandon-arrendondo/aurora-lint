/*
 * Rule: ERR33-C
 * Status: FAIL - fwprintf() returns a negative value on error. ERR33-C-EX1
 * exempts it only when the output is directed to stdout or stderr; this
 * writes to a file.
 */

#include <stdio.h>
#include <wchar.h>

void log_entry(FILE *log, const wchar_t *msg) {
    fwprintf(log, L"%ls\n", msg);
}
