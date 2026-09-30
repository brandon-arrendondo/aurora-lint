/*
 * Rule: ERR33-C
 * Status: FAIL - casting the result to size_t does not make an int hold
 * it unsigned: n is -1 on an encoding error, and `n < -2` misses it.
 */

#include <stddef.h>
#include <wchar.h>

int f(const char *s, mbstate_t *st) {
    wchar_t wc;
    int n = (size_t)mbrtowc(&wc, s, 4, st);
    if (n < -2) {
        return -1;
    }
    return n;
}
