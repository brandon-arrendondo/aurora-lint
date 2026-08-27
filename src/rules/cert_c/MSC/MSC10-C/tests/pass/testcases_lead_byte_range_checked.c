/*
 * Rule: MSC10-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MSC10-C violation
 * Description: A validator that rejects overlong forms at the byte level
 * instead of after decoding: C0/C1 are always overlong lead bytes, an E0
 * lead requires a second byte >= A0, and an F0 lead requires a second
 * byte >= 90. Structurally equivalent protection, so this must stay
 * clean.
 */

int utf8_validate(const unsigned char *s, unsigned long n) {
    unsigned long i = 0;

    while (i < n) {
        unsigned char c = s[i];

        if ((c & 0x80) == 0) {
            i += 1;
        } else if ((c & 0xe0) == 0xc0) {
            if (c < 0xc2) return 0;               /* C0/C1 are overlong */
            if ((s[i + 1] & 0xc0) != 0x80) return 0;
            i += 2;
        } else if ((c & 0xf0) == 0xe0) {
            if (c == 0xe0 && s[i + 1] < 0xa0) return 0;
            if ((s[i + 1] & 0xc0) != 0x80) return 0;
            if ((s[i + 2] & 0xc0) != 0x80) return 0;
            i += 3;
        } else if ((c & 0xf8) == 0xf0) {
            if (c == 0xf0 && s[i + 1] < 0x90) return 0;
            if ((s[i + 1] & 0xc0) != 0x80) return 0;
            if ((s[i + 2] & 0xc0) != 0x80) return 0;
            if ((s[i + 3] & 0xc0) != 0x80) return 0;
            i += 4;
        } else {
            return 0;
        }
    }
    return 1;
}
