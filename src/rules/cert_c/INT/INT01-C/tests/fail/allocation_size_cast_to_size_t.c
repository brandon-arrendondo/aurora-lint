/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - a size held in an int and cast to size_t
 *
 * The size expression is a size_t, but the size itself, psk_len, is held
 * in an int: the object INT01-C asks to be declared size_t.
 */
#include <stdlib.h>

int key_length(void);

void *make_hex(void) {
    int psk_len = key_length();
    return malloc((size_t)psk_len * 2 + 1);
}
