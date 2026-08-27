/*
 * Rule: MSC10-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC10-C violation
 * Description: The reference validator published on CERT's MSC10-C page.
 * It checks that each lead byte is followed by the right number of
 * 10xxxxxx continuation bytes, but never rejects non-shortest (overlong)
 * forms -- CERT's own page notes it "does not reject non-minimal forms".
 * So 'C0 80' is accepted as U+0000 and '2F C0 AE 2E 2F' as '/../'
 * (CWE-176, CWE-116).
 */

int spc_utf8_isvalid(const unsigned char *input) {
    int nb;
    const unsigned char *c = input;

    for (c = input; *c; c += (nb + 1)) {
        if (!(*c & 0x80)) nb = 0;
        else if ((*c & 0xc0) == 0x80) return 0;
        else if ((*c & 0xe0) == 0xc0) nb = 1;
        else if ((*c & 0xf0) == 0xe0) nb = 2;
        else if ((*c & 0xf8) == 0xf0) nb = 3;
        else if ((*c & 0xfc) == 0xf8) nb = 4;
        else if ((*c & 0xfe) == 0xfc) nb = 5;

        while (nb-- > 0)
            if ((*(c + nb) & 0xc0) != 0x80) return 0;
    }
    return 1;
}
