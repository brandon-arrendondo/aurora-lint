/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * `o = (oid_data *) buf` binds `o` to the very block `buf` holds -- a cast
 * changes the type a pointer is read through, never which allocation it
 * names. Reading the cast as an opaque right-hand side left `o` outside the
 * alias set, so the free of `buf` was credited to `buf` alone and every
 * return below reported `o` as leaked.
 */

#include <stdlib.h>

typedef struct {
    unsigned int oid;
    unsigned int length;
    char data[1];
} oid_data;

int query_oid(unsigned int oid, char *out, unsigned int len) {
    char *buf;
    oid_data *o;

    buf = malloc(sizeof(*o) + len);
    if (buf == NULL) {
        return -1;
    }
    o = (oid_data *) buf;
    o->oid = oid;
    o->length = len;

    if (o->length > len) {
        free(buf);
        return -1;
    }

    out[0] = o->data[0];
    free(buf);
    return 0;
}
