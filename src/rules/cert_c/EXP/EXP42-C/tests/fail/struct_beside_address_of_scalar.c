/*
 * Rule: EXP42-C
 * Source: aurora-lint
 * Status: FAIL - a struct with padding compared by its address
 *
 * The first memcmp compares two ints and is fine. The second compares two
 * structures with padding between their members, taken by address in the
 * same way.
 */
#include <string.h>

struct record {
    char tag;
    int value;
};

int same_int(int x, int y) {
    return memcmp(&x, &y, sizeof x) == 0;
}

int same_record(void) {
    struct record r1 = {0}, r2 = {0};
    return memcmp(&r1, &r2, sizeof r1) == 0;
}
