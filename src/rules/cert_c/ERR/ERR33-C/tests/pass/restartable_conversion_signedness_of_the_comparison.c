/*
 * Rule: ERR33-C
 * Status: PASS - an ordering against a negative constant below -1 tests a
 * restartable conversion when the comparison is unsigned: the result is
 * stored in a size_t, where (size_t)-1 is above every count, or the
 * constant is cast to size_t, which converts a signed store as well. And
 * stored signed, `n < 0` sees -1 directly.
 */

#include <wchar.h>

int f(const char *s, mbstate_t *st) {
    wchar_t wc;
    size_t n = mbrtowc(&wc, s, 4, st);
    if (n > -3) {
        return -1;
    }
    int m = mbrtowc(&wc, s, 4, st);
    if (m >= (size_t)-2) {
        return -1;
    }
    int k = mbrlen(s, 4, st);
    if (k < 0) {
        return -1;
    }
    return (int)n + m + k;
}
