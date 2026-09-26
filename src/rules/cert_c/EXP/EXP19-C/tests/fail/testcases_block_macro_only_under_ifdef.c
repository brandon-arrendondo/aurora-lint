/*
 * Rule: EXP19-C
 * Source: testcases
 * Status: FAIL - a macro that is a { } block only under #ifdef leaves the
 * body unbraced in every other build, where the name is the library call
 */

#include <string.h>

#ifdef INLINE_MEMCPY
# define memcpy(D,S,N) {char*xxd=(char*)(D);const char*xxs=(const char*)(S);\
                        int xxn=(N);while(xxn-->0)*(xxd++)=*(xxs++);}
#endif

void copy(char *dst, const char *src, int n) {
    if (n > 0)
        memcpy(dst, src, n)
    else
        dst[0] = 0;
}
