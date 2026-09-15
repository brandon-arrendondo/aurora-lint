/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: The guard for crediting a free through a cast alias. Nothing
 * here releases the block -- `o = (oid_data *) buf` only gives it a second
 * name -- so the leak must still be reported. Alias credit is for a free
 * that happened, not for the aliasing itself.
 */

#include <stdlib.h>

typedef struct {
    unsigned int oid;
    char data[1];
} oid_data;

int build_oid(unsigned int oid, unsigned int len) {
    char *buf;
    oid_data *o;

    buf = malloc(sizeof(*o) + len);
    if (buf == NULL) {
        return -1;
    }
    o = (oid_data *) buf;
    o->oid = oid;
    return 0;
}
