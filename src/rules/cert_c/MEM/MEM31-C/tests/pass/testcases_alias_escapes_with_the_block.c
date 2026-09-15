/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * Returning the block hands the caller every name for it. `hdr` is the same
 * allocation `buf` is, viewed as a header, so crediting the escape to `buf`
 * alone reported `hdr` as leaked at the very return that gives it away.
 */

#include <stdlib.h>

struct wire_hdr {
    unsigned int type;
    unsigned int len;
};

unsigned char *build_frame(unsigned int type, unsigned int len) {
    unsigned char *buf;
    struct wire_hdr *hdr;

    buf = malloc(sizeof(*hdr) + len);
    if (buf == NULL) {
        return NULL;
    }
    hdr = (struct wire_hdr *) buf;
    hdr->type = type;
    hdr->len = len;

    return buf;
}
