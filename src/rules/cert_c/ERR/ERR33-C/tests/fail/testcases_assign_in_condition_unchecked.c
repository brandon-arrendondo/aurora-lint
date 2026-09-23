/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: FAIL - Should trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: FAIL
 * Reason: The result is assigned inside a condition but the condition does
 *         not TEST it: it is dereferenced, passed to another call, or used in
 *         arithmetic. Sitting inside an `if` is not a check.
 */

#include <stdio.h>
#include <stdlib.h>

struct s {
    int x;
};

extern int consume(void *);

int dereferenced(void) {
    struct s *p;
    if ((p = malloc(sizeof *p))->x) { // VIOLATION: dereferenced, never tested
        return 1;
    }
    return 0;
}

int passed_on(size_t n) {
    void *p;
    if (consume(p = malloc(n))) { // VIOLATION: passed on, never tested
        return 1;
    }
    return 0;
}

int arithmetic(FILE *f) {
    long pos;
    if ((pos = ftell(f)) + 1) { // VIOLATION: computed with, never tested
        return 1;
    }
    return 0;
}

int main(void) {
    return 0;
}

/* strtoul signals a failed or overflowing conversion through errno, not its
 * value: comparing the value in the condition reads nothing of that. */
unsigned long strtoul_value_only(const char *s) {
    unsigned long mask;
    if ((mask = strtoul(s, NULL, 8)) > 0777) { // VIOLATION: errno never consulted
        return 0;
    }
    return mask;
}
