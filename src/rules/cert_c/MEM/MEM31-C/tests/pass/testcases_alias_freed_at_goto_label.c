/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * The cleanup label frees the block under the name the allocation was
 * written to. Every `goto` reaching that label therefore releases it under
 * the other names too -- `eth` here is the same block as `buf`. Matching the
 * label's free set by name alone reported a potential leak of `eth` at each
 * goto.
 */

#include <stdlib.h>

struct eth_hdr {
    unsigned char dst[6];
    unsigned short type;
};

extern int hexstr2bin(const char *hex, unsigned char *out, unsigned int len);

int send_test_frame(const char *cmd, unsigned int len) {
    unsigned char *buf;
    struct eth_hdr *eth;
    int res = -1;

    buf = malloc(len);
    if (buf == NULL) {
        return -1;
    }
    if (hexstr2bin(cmd, buf, len) < 0) {
        goto done;
    }
    eth = (struct eth_hdr *) buf;
    if (eth->type == 0) {
        goto done;
    }
    res = 0;
done:
    free(buf);
    return res;
}
