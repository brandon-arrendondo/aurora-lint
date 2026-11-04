/*
 * Rule: EXP19-C
 * Source: testcases
 * Status: PASS - a macro's replacement list is not code the rule reads, with a
 * comment inside it or without one: the comment no longer cuts the #define
 * short and leaves the rest of the body parsed as statements
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
