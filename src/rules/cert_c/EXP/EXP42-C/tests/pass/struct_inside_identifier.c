/*
 * Rule: EXP42-C
 * Source: aurora-lint (misfire: "struct" inside an identifier read as a struct type)
 * Status: PASS - Should NOT trigger EXP42-C violation
 *
 * The sizes are those of variables whose names merely contain the letters
 * "struct". No structure is compared.
 */
#include <string.h>

int restructure_count;
long destruct_len;

int same_count(const char *p, const char *q) {
    return memcmp(p, q, sizeof(restructure_count)) == 0;
}

int same_len(const char *p, const char *q) {
    return memcmp(p, q, sizeof destruct_len) == 0;
}

int same_cast(const void *p, const void *q) {
    return memcmp((const char *)p, (const char *)q, sizeof destruct_len) == 0;
}
