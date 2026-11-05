/*
 * Rule: PRE10-C
 * Source: aurora-lint
 * Status: PASS - DECODE_LENGTH wraps its statements in do { ... } while (0).
 *         The comment opener inside a string on one of its continued lines
 *         no longer cuts the #define short, which left only the part before
 *         it to read as the macro, and no while (0) in that part.
 */
void log_bad(const char *msg);

#define DECODE_LENGTH(ptr, enc, size, len)                   \
    do {                                                     \
        if ((enc) < 16) {                                    \
            (size) = 1;                                      \
            (len) = (ptr)[0] & 0x3f;                         \
        } else {                                             \
            log_bad("bad /* encoding");                    \
            (size) = 0;                                      \
            (len) = 0;                                       \
        }                                                    \
    } while (0)

/* Writes the low byte of len. */
int store_prev_length(unsigned char *p, unsigned int len) {
    if (p != 0) {
        p[0] = (unsigned char)(len & 0xffu);
    }
    return 1;
}

unsigned int entry_length(unsigned char *p) {
    unsigned int size, len;
    DECODE_LENGTH(p, p[0], size, len);
    return size + len + (unsigned int)store_prev_length(0, len);
}

unsigned int next_entry(unsigned char *p) {
    return entry_length(p) + entry_length(p + 1);
}
