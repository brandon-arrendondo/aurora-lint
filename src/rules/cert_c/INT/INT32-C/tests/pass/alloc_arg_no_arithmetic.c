/*
 * Rule: INT32-C
 * Source: pure-ftpd (real-world FP cohort, task 915)
 * Status: PASS - Should NOT trigger INT32-C violation
 * Description: Allocation arguments that contain no arithmetic operator at
 * all were flagged as "contains arithmetic that may overflow" because the
 * check scanned the argument's raw text: '->' matched as '-' and the deref
 * in 'sizeof *p' matched as '*'. Separately, realloc()'s first argument is
 * the pointer being resized, never a size computation, but every argument
 * was being checked as though it were the size.
 */

#include <stdlib.h>

struct hash_data {
    void *hash1_list;
    unsigned int sizeof_buf;
};

struct glob_data {
    char **gl_pathv;
};

void *bare_sizeof_deref(struct hash_data *p) {
    return malloc(sizeof *p);
}

void *bare_sizeof_parenthesized(struct hash_data *p) {
    return malloc(sizeof(*p));
}

void *bare_member_access(struct hash_data *ul) {
    return malloc(ul->sizeof_buf);
}

void *realloc_pointer_arg_member(struct glob_data *pglob, size_t n) {
    return realloc(pglob->gl_pathv, n);
}

void *realloc_pointer_arg_deref(char ***argv_p, size_t n) {
    return realloc(*argv_p, n);
}

void *realloc_pointer_arg_offset(char *base, unsigned int off, size_t n) {
    /* Pointer arithmetic on the resize target is not a signed size
     * computation -- ARR30-C's concern, not INT32-C's. */
    return realloc(base + off, n);
}
