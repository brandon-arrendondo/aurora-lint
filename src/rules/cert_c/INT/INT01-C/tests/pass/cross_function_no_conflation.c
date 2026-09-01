/*
 * Rule: INT01-C
 * Source: task 418 (task-389 sweep, whole-file size_t_vars/int_vars conflation)
 * Status: PASS - Should NOT trigger INT01-C violation
 *
 * `size_t_vars`/`int_vars` were previously built by a single
 * whole-translation-unit walk with no per-function reset, so `func_a`'s
 * `size_t len` parameter sat in `size_t_vars` alongside `func_b`'s
 * unrelated, same-named plain `int len` local, and an ordinary int-to-int
 * comparison in `func_b` (`i < len`, both genuinely `int`) was misread as
 * "int compared with size_t" for a size_t that only exists in `func_a`.
 */
#include <stddef.h>

void func_a(size_t len) {
    (void)len;
}

void func_b(void) {
    int i;
    int len;
    len = 10;
    for (i = 0; i < len; i++) {
        /* nothing */
    }
    (void)i;
}
