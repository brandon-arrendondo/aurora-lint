/*
 * Rule: EXP42-C
 * Source: aurora-lint
 * Status: FAIL - a struct with padding compared over its whole size
 *
 * The first memcmp's size is a variable whose name contains "struct"; the
 * second's is a structure type named with the struct keyword.
 */
#include <string.h>

struct header {
    char kind;
    double stamp;
};

int restructure_count;

int same_count(const char *p, const char *q) {
    return memcmp(p, q, sizeof restructure_count) == 0;
}

int same_header(const struct header *a, const struct header *b) {
    return memcmp(a, b, sizeof(struct header)) == 0;
}
