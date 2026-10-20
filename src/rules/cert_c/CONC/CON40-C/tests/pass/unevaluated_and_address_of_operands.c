/*
 * Rule: CON40-C
 * Source: testcases
 * Status: PASS - Should not trigger CON40-C violation
 *
 * The operands of sizeof, _Alignof and & are not accesses, nor is a
 * _Generic controlling expression: none of these expressions reads the
 * atomic object twice. Two different elements of an array are two
 * objects.
 */

#include <stdatomic.h>
#include <string.h>

static _Atomic int total;
static atomic_int counts[4];

int scaled(void) {
    return (int)sizeof total * total;
}

int same_address(void) {
    return &total == &total;
}

int aligned(void) {
    return (int)_Alignof(total) + total;
}

int kind(void) {
    return _Generic(total + total, int: 1, default: 0);
}

int compare(void) {
    return memcmp(&total, &total, sizeof total);
}

int pair(void) {
    return counts[0] * counts[1];
}
