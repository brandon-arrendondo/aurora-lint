/*
 * Rule: EXP19-C
 * Source: testcases
 * Status: PASS - the `} while (0)` closing a macro's do { ... } is not a
 * while statement, even when a comment inside the #define makes the parser
 * read the rest of the body as code
 */

#define DECODE(ptr, size, out)                          \
    do {                                                \
        if ((size) == 1) {                              \
            (out) = (ptr)[0];                           \
        } else { /* size == 5 */                        \
            (out) = (ptr)[4];                           \
        }                                               \
    } while (0)

int decode(unsigned char *p, int size) {
    int v;
    DECODE(p, size, v);
    return v;
}
