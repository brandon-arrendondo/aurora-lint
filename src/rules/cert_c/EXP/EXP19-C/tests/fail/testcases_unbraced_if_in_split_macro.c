/*
 * Rule: EXP19-C
 * Source: testcases
 * Status: FAIL - an unbraced if inside a macro body is still unbraced when a
 * comment makes the parser read the rest of the body as code
 */

#define LENGTH(enc, len)                                \
    do {                                                \
        if ((enc) < 16) {                               \
            (len) = 0; /* short form */                 \
        } else {                                        \
            if ((enc) == 17)                            \
                (len) = 1;                              \
            else                                        \
                (len) = 2;                              \
        }                                               \
    } while (0)

int length(int enc) {
    int len;
    LENGTH(enc, len);
    return len;
}
