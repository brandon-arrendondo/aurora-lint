/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: PASS - an int compared with an int or a ssize_t, not with a size_t
 *
 * A size_t n is declared in one block of the function and an int n in
 * another; the comparison is with the int. ssize_t is a signed type, not
 * size_t. An int i is declared in one function and a word i, an unsigned
 * type, in another; that one's comparison with a size_t is unsigned.
 */
#include <stddef.h>
#include <sys/types.h>

typedef unsigned int word;

int scan(const char *s, ssize_t len) {
    int i;
    int hits = 0;
    {
        size_t n = 4;
        hits += (int)n;
    }
    {
        int n = 8;
        for (i = 0; i < n; ++i) {
            hits += s[i];
        }
    }
    for (i = 0; i < len; ++i) {
        hits += s[i];
    }
    return hits;
}

int sum_words(const word *w, size_t n) {
    int total = 0;
    {
        int i = 0;
        total += i;
    }
    {
        word i;
        for (i = 0; i < n; ++i) {
            total += (int)w[i];
        }
    }
    return total;
}
