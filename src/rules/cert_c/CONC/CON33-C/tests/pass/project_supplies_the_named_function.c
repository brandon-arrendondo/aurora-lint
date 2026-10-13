/*
 * Rule: CON33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON33-C violation
 *
 * Each call below is named like a library function that is not thread-safe,
 * but none of them reaches that function. One goes through a macro that the
 * project defines under the library's name. One goes through a function the
 * file defines itself. One goes through a pointer parameter.
 */

#include <string.h>
#include <time.h>

char *tokenize_r(char *s, const char *delim, char **save);
extern char *save_slot;

#define strtok(s, d) tokenize_r(s, d, &save_slot)

char *first_word(char *line) { return strtok(line, " "); }

static char *strerror(int code) { return code ? "failed" : "ok"; }

const char *describe(int code) { return strerror(code); }

struct tm *convert(struct tm *(*localtime)(const time_t *), const time_t *t) {
  return localtime(t);
}
