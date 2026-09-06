/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: PASS
 * Reason: A <ctype.h> classifier is false for the null terminator, so
 *         `while (isX(*p)) p++;` stops at the end of a terminated string
 *         exactly as `while (*p != 0) p++;` does -- the terminator test
 *         written as a predicate. Covers the bare classifier, the
 *         project-local wrapper spellings real codebases reach it through
 *         (sqlite3Isdigit, IS_DIGIT, lisdigit), the (unsigned char)
 *         coercion wrapper around the argument, and the classifier as one
 *         conjunct of a compound condition.
 */

#include <ctype.h>

#define IS_DIGIT(c) isdigit(c)
#define UCHAR(c) ((unsigned char)(c))

static int sqlite3Isdigit(int c) { return c >= '0' && c <= '9'; }
static int lisdigit(int c) { return c >= '0' && c <= '9'; }
static int cast_uchar(int c) { return (unsigned char)c; }

int skip_digits_bare(const char *z) {
    int n = 0;
    while (isdigit(*z)) {
        n += *z;
        z++;
    }
    return n;
}

int skip_digits_project_wrapper(const char *z) {
    int n = 0;
    while (sqlite3Isdigit(*z)) {
        n += *z;
        z++;
    }
    return n;
}

int skip_digits_macro_alias(const char *params) {
    int n = 0;
    while (IS_DIGIT(*params)) {
        n += *params;
        params++;
    }
    return n;
}

int skip_space_cast_wrapper(const char *p) {
    int n = 0;
    while (isspace(UCHAR(*p))) {
        n += *p;
        p++;
    }
    return n;
}

int skip_digits_call_wrapper(const char **pc) {
    int n = 0;
    while (lisdigit(cast_uchar(**pc))) {
        n += **pc;
        (*pc)++;
    }
    return n;
}

int skip_digits_conjunct(const char *curr, int end_not_reached) {
    int n = 0;
    while (end_not_reached && IS_DIGIT(*curr)) {
        n += *curr;
        curr++;
    }
    return n;
}
