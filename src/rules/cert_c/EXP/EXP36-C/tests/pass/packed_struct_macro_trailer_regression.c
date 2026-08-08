/*
 * Rule: EXP36-C
 * Source: hostap ground-truth audit (task 159 adversarial pass) / task 395
 * Status: PASS - Casting into a packed struct can never increase alignment
 * Regression: hostap-style `struct foo { ... } STRUCT_PACKED;` where
 * STRUCT_PACKED is a `#define`d packed-attribute macro. sqc has no
 * preprocessor, so the trailing macro token parses as a declarator, not an
 * attribute -- resolving it via the macro's own definition text (rather
 * than the specific name "STRUCT_PACKED") keeps the fix codebase-independent.
 */

#define STRUCT_PACKED __attribute__ ((packed))

struct wire_hdr {
    unsigned short field_control;
    unsigned short duration;
} STRUCT_PACKED;

void parse_frame(unsigned char *buf) {
    struct wire_hdr *hdr = (struct wire_hdr *) buf;
    (void)hdr;
}
