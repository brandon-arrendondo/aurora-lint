/*
 * Rule: EXP36-C
 * Source: hostap ground-truth audit (task 159 adversarial pass) / task 395
 * Status: PASS - Casting into a packed struct can never increase alignment
 * Regression: the cast target type text can carry a `const`/`volatile`
 * qualifier before the struct keyword (e.g. `(const struct foo *)`) --
 * the packed-struct check must strip that qualifier before matching the
 * struct name, or it silently falls through to the unqualified alignment
 * table and still flags the cast.
 */

struct __attribute__((packed)) wire_hdr {
    unsigned short field_control;
    unsigned short duration;
};

void parse_frame(const unsigned char *buf) {
    const struct wire_hdr *hdr = (const struct wire_hdr *) buf;
    (void)hdr;
}
