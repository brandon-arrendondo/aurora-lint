/*
 * Rule: EXP34-C
 * Source: testcases (task 757 -- macro-forwarding null tolerance)
 * Status: PASS - Should NOT trigger EXP34-C
 *
 * hostap's `#define os_free(p) free((p))` (src/utils/os.h) is a transparent
 * wrapper around free(), and free(NULL) is a defined no-op (C11 7.22.3.3),
 * so os_free tolerates a possibly/definitely-null argument exactly like
 * free() does. This is derived from the macro's own expansion
 * (macro_expand::macro_forwarding_target), not a name-specific table entry --
 * any macro shaped like a transparent forwarder to a null-safe function gets
 * the same credit.
 *
 * `os_free` below is ALSO given a real function body (standing in for
 * hostap's os_unix.c, which provides a real `os_free` for a different build
 * config) with no null check of its own -- so the callsite null-argument
 * check has a FunctionSummary to consult and would flag this call if the
 * macro-derived null-safety weren't checked first.
 */

#define os_free(p) free((p))

void real_free_impl(void *ptr);

void os_free(void *ptr) {
    real_free_impl(ptr);
}

void use_buf(void) {
    char *buf = 0;
    os_free(buf);
}
