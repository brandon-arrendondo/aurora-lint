/*
 * Rule: FIO47-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO47-C violation
 *
 * get_data_arguments() used its own skip-count heuristic
 * (`starts_with('f') ? 2 : 1`) instead of the correct per-function table
 * already used by count_arguments()/extract_format_string(). For
 * snprintf/vsnprintf this skipped only 1 argument instead of 3 (buf, size,
 * fmt), shifting every zipped specifier/argument pair by 2 positions -
 * pairing the first real specifier against the buffer or size parameter,
 * and sometimes against the format string literal itself. Wrapping the
 * call in an outer macro (a pervasive idiom in real code, e.g. a
 * truncation-checking SNCHECK(call, size) macro) doesn't change any of
 * this - it is triggered by any multi-argument snprintf call.
 */
#include <stdio.h>

#define SNCHECK(call, size) ((call) < 0 || (size_t)(call) >= (size))

void format_entry(char *line, size_t line_size, const char *name, char kind, unsigned long long value) {
    if (!SNCHECK(snprintf(line, line_size,
                          "%s type=%c size=%llu\n",
                          name, kind, value), line_size)) {
        /* write line */
    }
}

int main(void) {
    char buf[128];
    format_entry(buf, sizeof buf, "example", 'f', 42ULL);
    return 0;
}
