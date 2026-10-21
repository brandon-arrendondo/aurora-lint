/*
 * Rule: EXP42-C
 * Source: aurora-lint (misfire: memcmp of &scalar read as a struct comparison)
 * Status: PASS - Should NOT trigger EXP42-C violation
 *
 * Each memcmp compares the bytes of an int, an enum or a pointer, taken by
 * address. None of these objects has padding, so no padding is compared.
 */
#include <string.h>

enum mode { MODE_A, MODE_B };

int same_int(void) {
    int x = 1, y = 2;
    return memcmp(&x, &y, sizeof x) == 0;
}

int same_long(long a, long b) {
    return memcmp(&a, &b, sizeof(long)) == 0;
}

int same_mode(enum mode m, enum mode n) {
    return memcmp(&m, &n, sizeof m) == 0;
}

int same_pointer(const char *p, const char *q) {
    return memcmp(&p, &q, sizeof p) == 0;
}
