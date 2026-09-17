/*
 * Rule: PRE32-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE32-C violation
 */

/*
 * Rule: PRE32-C - Do not use preprocessor directives in invocations of function-like macros
 * Status: PASS
 * Reason: The #ifdef/#elif/#else selects between complete alternative
 * sub-expressions inside a plain `if (...)` condition. It does not split
 * the argument list of any call, macro-like or otherwise - an earlier,
 * already-closed call elsewhere in the file (here memcpy()) must not be
 * blamed for it. Modeled on a real false positive found in pure-ftpd's
 * alt_arc4random.c.
 */

#include <string.h>
#include <sys/stat.h>

void copy_something(char *dest, const char *src) {
    memcpy(dest, src, 12);
}

int check_device(struct stat *st, int ok) {
    if (ok == 0 &&
#ifdef __COMPCERT__
        1
#elif defined(S_ISNAM)
        (S_ISNAM(st->st_mode) || S_ISCHR(st->st_mode))
#else
        S_ISCHR(st->st_mode)
#endif
       ) {
        return 1;
    }
    return 0;
}

int main(void) {
    return 0;
}
