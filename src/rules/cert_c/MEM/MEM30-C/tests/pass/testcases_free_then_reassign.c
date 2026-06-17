/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM30-C violation
 */

/*
 * Rule: MEM30-C - Do not access freed memory
 * Status: PASS
 * Reason: Reassigning a pointer to a fresh allocation overwrites the dangling
 *         pointer, so it is no longer freed. Real code reassigns through
 *         allocator WRAPPERS (mosquitto_malloc, curlx_calloc, Curl_strdup),
 *         sometimes cast-wrapped. Flagging the post-reassign NULL-check or use
 *         as use-after-free was the free-then-reassign FP (task 181 pattern 1).
 */

#include <stdlib.h>

extern char *pkg_malloc(unsigned long n);
extern char *pkg_calloc(unsigned long n, unsigned long sz);
extern char *pkg_strdup(const char *s);

char *grow(char *buf, unsigned long n) {
    free(buf);
    buf = pkg_malloc(n);      /* wrapper allocation clears dangling state */
    if (buf == NULL) {        /* not a use-after-free */
        return NULL;
    }
    buf[0] = '\0';            /* not a use-after-free */
    return buf;
}

char *grow_cast(char *buf, unsigned long n) {
    free(buf);
    buf = (char *)pkg_calloc(1, n);  /* cast-wrapped wrapper allocation */
    buf[0] = '\0';                   /* not a use-after-free */
    return buf;
}

char *replace(char *buf, const char *src) {
    free(buf);
    buf = pkg_strdup(src);    /* strdup-family wrapper also reallocates */
    return buf;
}
