/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: Twin of tests/pass/testcases_safe_free_macro_at_tail.c.
 * Reading a freeing macro by what its body does must cut both ways: a
 * macro that frees WITHOUT nulling leaves the pointer dangling exactly as
 * a bare free() does, so invoking it twice is a double free, and a leak on
 * a path it never runs on is still a leak.
 */

#include <stdlib.h>

#define curlx_free free
#define discard(ptr) curlx_free(ptr)

extern int use(const char *s);

int free_only_macro_twice(void) {
    char *p = malloc(16);
    discard(p);
    discard(p);
    return 0;
}

int early_return_skips_the_macro(int c) {
    char *p = malloc(16);
    if (c) {
        return -1;
    }
    use(p);
    discard(p);
    return 0;
}
