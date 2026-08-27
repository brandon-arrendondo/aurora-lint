/*
 * Rule: MSC10-C
 * Source: testcases
 * Status: FAIL - Should trigger MSC10-C violation
 * Description: A hand-rolled decoder that assembles the code point from
 * the payload bits and validates continuation bytes, but never compares
 * the decoded value against the minimum for its byte length -- so an
 * overlong encoding decodes silently to a short code point.
 */

unsigned long utf8_decode(const unsigned char *s, int *len) {
    unsigned long cp;
    int i, nb;

    if ((s[0] & 0x80) == 0) {
        nb = 0;
        cp = s[0];
    } else if ((s[0] & 0xe0) == 0xc0) {
        nb = 1;
        cp = s[0] & 0x1f;
    } else if ((s[0] & 0xf0) == 0xe0) {
        nb = 2;
        cp = s[0] & 0x0f;
    } else if ((s[0] & 0xf8) == 0xf0) {
        nb = 3;
        cp = s[0] & 0x07;
    } else {
        return 0;
    }

    for (i = 1; i <= nb; i++) {
        if ((s[i] & 0xc0) != 0x80) {
            return 0;
        }
        cp = (cp << 6) | (s[i] & 0x3f);
    }

    *len = nb + 1;
    return cp;
}
