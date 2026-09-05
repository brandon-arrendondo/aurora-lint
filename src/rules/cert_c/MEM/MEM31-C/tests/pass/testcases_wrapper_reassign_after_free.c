/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * octet_string_str() is a user-defined allocator wrapper whose name matches
 * neither the literal allocation-function list (malloc/calloc/realloc/
 * strdup/strndup) nor the create_*/alloc_*/new_*/make_*/build_*/*_alloc/
 * *_create/*_new/*_dup naming heuristic. Its body is scanned by
 * FunctionSummary and found to malloc() and return the result, so
 * reassigning through it after a free must clear the freed-state for the
 * destination variable -- otherwise the later free() below is a false
 * double-free against stale state from the earlier free(txt).
 */

#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned char *data;
    size_t len;
} octet_string;

char *octet_string_str(const octet_string *hash) {
    char *out = malloc(hash->len * 2 + 1);
    if (!out) {
        return NULL;
    }
    memset(out, 0, hash->len * 2 + 1);
    return out;
}

void process(octet_string *hash) {
    char *txt = octet_string_str(hash);
    if (!txt) {
        return;
    }

    /* first use, then free */
    free(txt);

    /* txt is reassigned to a fresh allocation from the wrapper */
    txt = octet_string_str(hash);
    if (!txt) {
        return;
    }

    /* second use of the *new* allocation */
    free(txt);
}
