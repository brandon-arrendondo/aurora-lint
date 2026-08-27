/*
 * Rule: INT32-C
 * Source: testcases
 * Status: FAIL - Should trigger INT32-C violation
 * Description: Overflow-prone size arithmetic computed one statement
 * before an allocation call, assigned to a variable, and then passed to
 * malloc() by that variable name. INT32-C already caught this when the
 * arithmetic was written directly inside malloc()'s argument list; this
 * case additionally requires walking back one assignment hop to the
 * statement that actually computed the size (task 604, modeled on a
 * real false negative in pure-ftpd's SQL-client logging code:
 * `to_len = from_len * 2U + 1U; ...; malloc(to_len);`).
 */

#include <stdlib.h>
#include <string.h>

char *escape_and_alloc(const char *from) {
    size_t from_len = strlen(from);
    size_t to_len;
    char *to;

    to_len = from_len * 2U + 1U;
    to = malloc(to_len);
    return to;
}
