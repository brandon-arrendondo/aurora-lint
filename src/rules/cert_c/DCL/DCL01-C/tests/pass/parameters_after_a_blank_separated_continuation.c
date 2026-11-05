/*
 * Rule: DCL01-C
 * Source: aurora-lint
 * Status: PASS - each function's p is its own parameter and nothing at file
 *         scope is named p. The blanks after a \ in DECODE_LENGTH's
 *         continued replacement list (a continuation to the compiler) no
 *         longer cut the #define short, which left the rest of the body read
 *         as code and the first function's parameter taken for a file-scope
 *         declaration that the later ones shadowed.
 */
#define DECODE_LENGTH(ptr, enc, size, len)                   \
    do {                                                     \
        if ((enc) < 16) {                                    \
            (size) = 1;                                      \
            (len) = (ptr)[0] & 0x3f;                         \
        } else {                                             \   
            (size) = 0;                                      \
            (len) = 0;                                       \
        }                                                    \
    } while (0)

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
