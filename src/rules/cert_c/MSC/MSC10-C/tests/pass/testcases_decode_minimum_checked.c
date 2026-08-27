/*
 * Rule: MSC10-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MSC10-C violation
 * Description: The same decoder shape as the fail fixtures, but it
 * rejects non-shortest forms by comparing the assembled code point
 * against the minimum legal value for its byte length. An overlong
 * 'C0 80' decodes to 0, fails the >= 0x80 floor, and is rejected.
 */

unsigned long utf8_decode_strict(const unsigned char *s, int *len) {
    unsigned long cp;
    unsigned long min;
    int i, nb;

    if ((s[0] & 0x80) == 0) {
        nb = 0;
        cp = s[0];
        min = 0;
    } else if ((s[0] & 0xe0) == 0xc0) {
        nb = 1;
        cp = s[0] & 0x1f;
        min = 0x80;
    } else if ((s[0] & 0xf0) == 0xe0) {
        nb = 2;
        cp = s[0] & 0x0f;
        min = 0x800;
    } else if ((s[0] & 0xf8) == 0xf0) {
        nb = 3;
        cp = s[0] & 0x07;
        min = 0x10000;
    } else {
        return 0;
    }

    for (i = 1; i <= nb; i++) {
        if ((s[i] & 0xc0) != 0x80) {
            return 0;
        }
        cp = (cp << 6) | (s[i] & 0x3f);
    }

    /* Reject non-shortest (overlong) encodings. */
    if (cp < min) {
        return 0;
    }

    *len = nb + 1;
    return cp;
}
