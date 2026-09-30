/*
 * Rule: ERR33-C
 * Status: FAIL - `u8` here is an unsigned char: `(u8)-2` is 254, which
 * promotes to int, so `n >= (u8)-2` is a signed comparison that never sees
 * the -1 an encoding error leaves in n.
 */

#include <wchar.h>

typedef unsigned char u8;

int f(const char *s, mbstate_t *st) {
    wchar_t wc;
    int n = mbrtowc(&wc, s, 4, st);
    if (n >= (u8)-2) {
        return -1;
    }
    return n;
}
