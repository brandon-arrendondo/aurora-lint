/*
 * Rule: ERR33-C
 * Status: FAIL - the result is stored in a type whose definition is not in
 * view, so its signedness is unknown. Read as signed, `n < -2` does not see
 * the -1 an encoding error leaves there.
 */

#include <wchar.h>

int f(const char *s, mbstate_t *st) {
    wchar_t wc;
    opaque_len_t n = mbrtowc(&wc, s, 4, st);
    if (n < -2) {
        return -1;
    }
    return (int)n;
}
