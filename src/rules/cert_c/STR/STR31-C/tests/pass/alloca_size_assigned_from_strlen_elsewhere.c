/*
 * Rule: STR31-C
 * Status: PASS - Should NOT trigger STR31-C violation
 * Reason: The alloca size is computed from a variable that another function
 * in the file assigns from strlen(), so the copy is sized for the string.
 * That assignment is outside the function holding the copy.
 */

#include <alloca.h>
#include <string.h>

static size_t n;

void init(const char *s) { n = strlen(s); }

void f(const char *s) {
    char *d;
    d = (char *)alloca((n + 1) * 1);
    strcpy(d, s);
}
