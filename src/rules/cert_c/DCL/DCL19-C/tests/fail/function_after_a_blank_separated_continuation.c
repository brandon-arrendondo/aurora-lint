/*
 * Rule: DCL19-C
 * Source: aurora-lint
 * Status: FAIL - store_prev_length has external linkage and only this file
 *         calls it. The blanks after a \ in DECODE_LENGTH's continued
 *         replacement list (a continuation to the compiler) no longer cut
 *         the #define short, so the rest of the body is not read as code
 *         that swallows the function after it.
 * Expect: count=1
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

int store_prev_length(unsigned char *p, unsigned int len) { /* Expect: here */
    if (p != 0) {
        p[0] = (unsigned char)(len & 0xffu);
    }
    return 1;
}

static unsigned int entry_length(unsigned char *p) {
    unsigned int size, len;
    DECODE_LENGTH(p, p[0], size, len);
    return size + len + (unsigned int)store_prev_length(0, len);
}

unsigned int first_entry_length(unsigned char *p) {
    return entry_length(p);
}
