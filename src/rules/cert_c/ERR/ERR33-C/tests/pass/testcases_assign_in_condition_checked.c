/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: PASS
 * Reason: The result is assigned inside the very condition that tests it
 *         . Compared, negated, a non-first `||` operand, a loop
 *         condition, a `?:` condition and a bare truthiness test all count.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void die_mem(void);

char *compared(const char *s) {
    char *p;
    if ((p = strdup(s)) == NULL) {
        die_mem();
    }
    return p;
}

void *negated(size_t n) {
    void *p;
    if (!(p = malloc(n))) {
        return NULL;
    }
    return p;
}

void *second_operand(int flag, size_t n) {
    void *answer = NULL;
    if (flag == 0 || (answer = malloc(n)) == NULL) {
        return NULL;
    }
    return answer;
}

int loop_condition(FILE *f) {
    int c;
    while ((c = fgetc(f)) != EOF) {
        putchar(c);
    }
    return 0;
}

void *ternary_condition(size_t n) {
    void *p;
    return (p = malloc(n)) ? p : NULL;
}

void *bare_truthiness(size_t n) {
    void *p;
    if ((p = malloc(n))) {
        return p;
    }
    return NULL;
}

int main(void) {
    return 0;
}

#include <errno.h>
#include <limits.h>

unsigned long strtoul_with_errno(const char *s) {
    unsigned long v;
    errno = 0;
    if ((v = strtoul(s, NULL, 10)) == ULONG_MAX && errno == ERANGE) {
        return 0;
    }
    return v;
}
