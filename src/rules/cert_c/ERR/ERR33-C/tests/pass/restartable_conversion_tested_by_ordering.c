/*
 * Rule: ERR33-C
 * Settings: data_model=lp64
 * Status: PASS - mbrtowc(), mbrlen(), mbrtoc16() and mbrtoc32() return
 * (size_t)-1 on an encoding error and (size_t)-2 (or -3) for an incomplete
 * or pending sequence. All of these sit above every byte count, so an
 * ordering against (size_t)-2 or (size_t)-3, in either direction, tests
 * for the error along with them.
 */

#include <uchar.h>
#include <wchar.h>

int f(const char *s, mbstate_t *st) {
    wchar_t wc;
    char16_t c16;
    char32_t c32;
    size_t n = mbrtowc(&wc, s, 4, st);
    if (n >= (size_t)-2) {
        return -1;
    }
    size_t m = mbrlen(s, 4, st);
    if ((size_t)-2 <= m) {
        return -1;
    }
    size_t k = mbrtoc32(&c32, s, 4, st);
    if (k > (size_t)-3) {
        return -1;
    }
    size_t j = mbrtoc16(&c16, s, 4, st);
    if (j < (size_t)-3) {
        return (int)(n + m + k + j);
    }
    return -1;
}
