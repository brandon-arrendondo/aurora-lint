/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * A struct field is tracked under its full spelling, and reassigning it
 * has the same meaning as reassigning a bare name: whatever `name->f`
 * holds afterwards, it is not the block that was freed under it. hostap's
 * x509v3.c frees `name->alt_email`, allocates it afresh, and frees it
 * again on a later error path -- a double free for as long as the freed
 * mark outlived the reassignment. And `free(oid.p); oid.p = NULL;`
 * (mbedtls x509_create.c) leaves nothing under the name to report at the
 * next return.
 */

#include <stdlib.h>
#include <string.h>

struct name { char *alt_email; };
struct buf { unsigned char *p; size_t len; };

int free_realloc_free_again(struct name *name, const char *pos, size_t len) {
    free(name->alt_email);
    name->alt_email = malloc(len + 1);
    if (name->alt_email == NULL) {
        return -1;
    }
    memcpy(name->alt_email, pos, len);
    if (strlen(name->alt_email) != len) {
        free(name->alt_email);
        name->alt_email = NULL;
        return -1;
    }
    return 0;
}

int free_then_null_then_return(int fail) {
    struct buf oid;
    oid.p = malloc(8);
    if (!oid.p) {
        return -1;
    }
    free(oid.p);
    oid.p = NULL;
    if (fail) {
        return -2;
    }
    return 0;
}
