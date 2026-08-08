/*
 * Rule: EXP36-C
 * Source: hostap ground-truth audit (task 159 adversarial pass) / task 395
 * Status: PASS - Casting into a packed struct can never increase alignment
 * Regression: a struct with __attribute__((packed)) has alignof == 1, so a
 * cast from a byte pointer into it is never an alignment-increasing cast.
 */

struct __attribute__((packed)) wire_hdr {
    unsigned short field_control;
    unsigned short duration;
};

void parse_frame(unsigned char *buf) {
    struct wire_hdr *hdr = (struct wire_hdr *) buf;
    (void)hdr;
}
